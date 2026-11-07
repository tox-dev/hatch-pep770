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
    # zip timestamps start at 1980
    entry = zipfile.ZipInfo(sbom, time.gmtime(max(epoch, 315532800))[:6])
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3  # Unix, whichever system writes the entry, so the bytes match across operating systems
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
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
            archive.repack([archive.remove(info) for info in stale])  # ty: ignore[unresolved-attribute] # zipremove adds both
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


def _rewritten_record(record: bytes, name: str, sbom: str, content: bytes) -> bytes:
    lines: Final[list[str]] = [
        line for line in record.decode("utf-8").splitlines(keepends=True) if not line.startswith(f"{sbom},")
    ]
    newline: Final[str] = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
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


__all__ = [
    "member_digest",
    "open_archive",
    "read_member",
    "read_wheel_metadata",
    "write_sbom",
]
