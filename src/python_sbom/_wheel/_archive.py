from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
import zipfile
import zlib
from collections import Counter
from contextlib import contextmanager
from email.parser import Parser
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final

from python_sbom._errors import WheelError

from ._record import record_line

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable
    from email.message import Message

# metadata files beyond this size are refused, so a hostile wheel cannot exhaust memory
_METADATA_LIMIT: Final[int] = 16 * 1024 * 1024
_CHUNK: Final[int] = 1024 * 1024


def write_sbom(wheel: Path, name: str, content: bytes, epoch: int) -> str:
    with open_archive(wheel, str(wheel)) as archive:
        entries: Final[list[tuple[zipfile.ZipInfo, bytes]]] = [
            (info, archive.read(info)) for info in archive.infolist()
        ]
    if (dist_info := _find_dist_info(info.filename for info, _ in entries)) is None:
        msg = f"{wheel} has no .dist-info/METADATA, so it is not a wheel"
        raise WheelError(msg)
    record: Final[str] = f"{dist_info}/RECORD"
    if record not in {info.filename for info, _ in entries}:
        msg = f"{wheel} has no {record}"
        raise WheelError(msg)
    sbom: Final[str] = f"{dist_info}/sboms/{name}"
    # zip timestamps start at 1980
    entry = zipfile.ZipInfo(sbom, time.gmtime(max(epoch, 315532800))[:6])
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3  # Unix, whichever system writes the entry, so the bytes match across operating systems
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    # the SBOM goes right before RECORD, which stays the last entry
    members: Final[list[tuple[zipfile.ZipInfo, bytes]]] = []
    for info, data in entries:
        if info.filename == record:
            members.extend([(entry, content), (info, _rewritten_record(data, record, sbom, content))])
        elif info.filename != sbom:
            members.append((info, data))
    # a name no "dist/*.whl" glob matches, in the wheel's directory so the final rename stays on one file system
    descriptor, temporary = tempfile.mkstemp(dir=wheel.parent, prefix=".python-sbom-", suffix=".tmp")
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for info, data in members:
                archive.writestr(info, data)
        Path(temporary).chmod(stat.S_IMODE(wheel.stat().st_mode))
        Path(temporary).replace(wheel)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return sbom


@contextmanager
def open_archive(file: Path | IO[bytes], where: str) -> Generator[zipfile.ZipFile, None, None]:
    try:
        with zipfile.ZipFile(file) as archive:
            # installers extract the first of two same-named members and zipfile reads the last, and a file system that
            # ignores case merges names that differ only by case, so such names would hide what gets installed
            if clashes := sorted(
                name for name, count in Counter(name.casefold() for name in archive.namelist()).items() if count > 1
            ):
                msg = f"{where} holds more than one member named {', '.join(clashes)}, ignoring case"
                raise WheelError(msg)
            yield archive
    except (zipfile.BadZipFile, zlib.error) as error:
        msg = f"{where} is not a valid zip archive: {error}"
        raise WheelError(msg) from error


def _find_dist_info(names: Iterable[str]) -> str | None:
    found = [name.split("/")[0] for name in names if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
    # a wheel holds one .dist-info; a second one is a decoy that could otherwise decide whose metadata counts
    if len(found) > 1:
        msg = f"the archive holds {len(found)} .dist-info directories, {', '.join(sorted(found))}, not one"
        raise WheelError(msg)
    return next(iter(found), None)


def _rewritten_record(record: bytes, name: str, sbom: str, content: bytes) -> bytes:
    lines: Final[list[str]] = [
        line for line in record.decode("utf-8").splitlines(keepends=True) if not line.startswith(f"{sbom},")
    ]
    newline: Final[str] = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    # the row of RECORD itself stays last
    at: Final[int] = next((index for index, line in enumerate(lines) if line.startswith(f"{name},")), len(lines))
    lines.insert(at, f"{record_line(sbom, content)}{newline}")
    return "".join(lines).encode()


def read_wheel_metadata(archive: zipfile.ZipFile, where: str) -> tuple[str, Message]:
    if (dist_info := _find_dist_info(archive.namelist())) is None:
        msg = f"{where} has no .dist-info/METADATA, so it is not a wheel"
        raise WheelError(msg)
    return dist_info, Parser().parsestr(read_member(archive, f"{dist_info}/METADATA", where).decode("utf-8"))


def read_member(archive: zipfile.ZipFile, name: str, where: str, limit: int = _METADATA_LIMIT) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        msg = f"{where} has no {name}"
        raise WheelError(msg) from error
    # counted as it decompresses, since the size the archive states may lie and one read decompresses it all at once
    content: Final[bytearray] = bytearray()
    with archive.open(info) as member:
        while chunk := member.read(_CHUNK):
            content.extend(chunk)
            if len(content) > limit:
                msg = f"{where}: {name} is over the {limit} byte limit"
                raise WheelError(msg)
    return bytes(content)


def member_digest(archive: zipfile.ZipFile, name: str | zipfile.ZipInfo, algorithm: str) -> str:
    digest: Final = hashlib.new(algorithm)
    with archive.open(name) as member:
        while chunk := member.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "member_digest",
    "open_archive",
    "read_member",
    "read_wheel_metadata",
    "write_sbom",
]
