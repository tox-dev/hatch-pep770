from __future__ import annotations

import csv
import hashlib
import os
import shutil
import stat
import tempfile
import time
import zipfile
import zlib
from collections import Counter
from contextlib import contextmanager
from io import BytesIO, StringIO
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final

import zipremove
from installer.records import Hash, RecordEntry
from installer.sources import WheelFile
from installer.utils import copyfileobj_with_hashing

from python_sbom._errors import WheelError
from python_sbom._model._metadata import CoreMetadata, parse_metadata

if TYPE_CHECKING:
    from collections.abc import Generator

# metadata files beyond this size are refused, so a hostile wheel cannot exhaust memory
_METADATA_LIMIT: Final[int] = 16 * 1024 * 1024
_CHUNK: Final[int] = 1024 * 1024
# 1980-01-01, the earliest time a zip entry holds
_ZIP_EPOCH: Final[int] = 315532800
# the zlib level each setting of the deflate option bits in a member's flags stands for (APPNOTE 4.4.4: normal, maximum,
# fast, super fast), as Info-ZIP sets them; None is zlib's default
_DEFLATE_LEVELS: Final[dict[int, int | None]] = {0b000: None, 0b010: 9, 0b100: 2, 0b110: 1}


def write_sbom(wheel: Path, name: str, content: bytes, epoch: int) -> str:
    with open_archive(wheel, str(wheel)) as archive:
        _, dist_info = _wheel_source(archive, str(wheel))
        record: Final[str] = f"{dist_info}/RECORD"
        if missing := sorted({f"{dist_info}/METADATA", record} - set(archive.namelist())):
            msg = f"{wheel} has no {', '.join(missing)}"
            raise WheelError(msg)
        record_info: Final[zipfile.ZipInfo] = archive.getinfo(record)
        record_data: Final[bytes] = archive.read(record_info)
    sbom: Final[str] = f"{dist_info}/sboms/{name}"
    entry: Final[zipfile.ZipInfo] = _entry(sbom, epoch)
    entry.compress_type = zipfile.ZIP_DEFLATED
    rewritten: Final[bytes] = _rewritten_record(record_data, record, sbom, content)
    # a name no "dist/*.whl" glob matches, in the wheel's directory so the final rename stays on one file system
    descriptor, temporary = tempfile.mkstemp(dir=wheel.parent, prefix=".python-sbom-", suffix=".tmp")
    os.close(descriptor)
    try:  # ruff: ignore[too-many-statements-in-try-clause] # whichever step fails, the temporary file goes
        # copied through the process: copy_file_range makes some file systems first flush the wheel just written
        with wheel.open("rb") as source, Path(temporary).open("wb") as target:
            shutil.copyfileobj(source, target)
        # the other members keep their bytes as stored, still compressed, so only the SBOM and RECORD get compressed
        # here; both go last, RECORD after the SBOM
        with zipremove.ZipFile(temporary, "a") as archive:
            stale = [info for info in archive.infolist() if info.filename in {record, sbom}]
            archive.repack(list(map(archive.remove, stale)))  # ty: ignore[unresolved-attribute] # zipremove adds both
            archive.writestr(entry, content)
            archive.writestr(record_info, rewritten)
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
            # ignores case merges names that differ only by case, so such names would hide what gets installed;
            # installer's WheelFile accepts names that differ only by case
            if clashes := sorted(
                name for name, count in Counter(name.casefold() for name in archive.namelist()).items() if count > 1
            ):
                msg = f"{where} holds more than one member named {', '.join(clashes)}, ignoring case"
                raise WheelError(msg)
            yield archive
    # zipfile raises these as late as a member's last read, inside installer's checks too, which let them through
    except (zipfile.BadZipFile, zlib.error) as error:
        msg = f"{where} is not a valid zip archive: {error}"
        raise WheelError(msg) from error


def _wheel_source(archive: zipfile.ZipFile, where: str) -> tuple[WheelFile, str]:
    # installer refuses a wheel whose file name does not parse, or that holds other than one top-level .dist-info, since
    # a second one is a decoy that could decide whose metadata counts
    try:
        wheel = WheelFile(archive)
        dist_info = wheel.dist_info_dir
    except ValueError as error:
        msg = f"{where} is not a wheel: {error}"
        raise WheelError(msg) from error
    return wheel, dist_info


def _entry(name: str, epoch: int) -> zipfile.ZipInfo:
    # zip times start at 1980; Unix attributes whichever system writes the entry, so the bytes match across systems
    entry: Final[zipfile.ZipInfo] = zipfile.ZipInfo(name, time.gmtime(max(epoch, _ZIP_EPOCH))[:6])
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    return entry


def _rewritten_record(record: bytes, name: str, sbom: str, content: bytes) -> bytes:
    lines: Final[list[str]] = [
        line for line in record.decode("utf-8").splitlines(keepends=True) if not line.startswith(f"{sbom},")
    ]
    newline: Final[str] = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    # a last row without its line end would take the SBOM's row onto its own line
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += newline
    # the row of RECORD itself stays last
    at: Final[int] = next((index for index, line in enumerate(lines) if line.startswith(f"{name},")), len(lines))
    # installer's helper hashes as it copies; the copy is thrown away
    digest, size = copyfileobj_with_hashing(BytesIO(content), BytesIO(), "sha256")
    row: Final[StringIO] = StringIO()
    csv.writer(row, lineterminator=newline).writerow(RecordEntry(sbom, Hash("sha256", digest), size).to_row())
    lines.insert(at, row.getvalue())
    return "".join(lines).encode()


def read_wheel_metadata(archive: zipfile.ZipFile, where: str) -> tuple[WheelFile, CoreMetadata]:
    wheel, dist_info = _wheel_source(archive, where)
    # read capped, as installer's read_dist_info decompresses the member whole
    return wheel, parse_metadata(read_member(archive, f"{dist_info}/METADATA", where).decode("utf-8"))


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


def append_member(archive: Path, name: str, content: bytes, epoch: int) -> None:
    with zipfile.ZipFile(archive, "a") as handle:
        if name in handle.namelist():
            msg = f"{archive.name} already holds {name}"
            raise WheelError(msg)
        # compressed by the method most of the archive's files use, at the level their deflate option bits name, since
        # the zip format records no level itself and Python's zipfile leaves the bits at normal, zlib's default;
        # directories and empty files count for none, as zip tools store them whatever they compress
        files: Final[list[zipfile.ZipInfo]] = [
            info for info in handle.infolist() if info.file_size and not info.is_dir()
        ]
        method: Final[int] = next(
            iter(Counter(info.compress_type for info in files).most_common(1)), (zipfile.ZIP_STORED, 0)
        )[0]
        flags: Final[int] = next((info.flag_bits for info in files if info.compress_type == method), 0)
        level: Final[int | None] = _DEFLATE_LEVELS[flags & 0b110] if method == zipfile.ZIP_DEFLATED else None
        handle.writestr(_entry(name, epoch), content, compress_type=method, compresslevel=level)


__all__ = [
    "append_member",
    "member_digest",
    "open_archive",
    "read_member",
    "read_wheel_metadata",
    "write_sbom",
]
