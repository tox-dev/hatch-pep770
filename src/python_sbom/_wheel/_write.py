"""Write the SBOM into a wheel and its RECORD, or append it to an archive."""

from __future__ import annotations

import csv
import os
import shutil
import stat
import tempfile
import time
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from typing import Final

import zipremove
from installer.records import Hash, RecordEntry
from installer.utils import copyfileobj_with_hashing

from python_sbom import SbomError

from ._zip import open_archive, wheel_source

# 1980-01-01, the earliest time a zip entry holds
_ZIP_EPOCH: Final[int] = 315532800


def write_sbom(wheel: Path, name: str, content: bytes, epoch: int) -> str:
    with open_archive(wheel, str(wheel)) as archive:
        _, dist_info = wheel_source(archive, str(wheel))
        record: Final[str] = f"{dist_info}/RECORD"
        if missing := sorted({f"{dist_info}/METADATA", record} - set(archive.namelist())):
            msg = f"{wheel} has no {', '.join(missing)}"
            raise SbomError(msg)
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
            archive.repack(list(map(archive.remove, stale)))  # ty: ignore[missing-attribute] # zipremove adds both
            archive.writestr(entry, content)
            archive.writestr(record_info, rewritten)
        Path(temporary).chmod(stat.S_IMODE(wheel.stat().st_mode))
        Path(temporary).replace(wheel)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return sbom


def _entry(name: str, epoch: int) -> zipfile.ZipInfo:
    # zip times start at 1980; Unix attributes whichever system writes the entry, so the bytes match across systems
    entry: Final[zipfile.ZipInfo] = zipfile.ZipInfo(name, time.gmtime(max(epoch, _ZIP_EPOCH))[:6])
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    return entry


def _rewritten_record(record: bytes, name: str, sbom: str, content: bytes) -> bytes:
    lines: Final[list[str]] = [line for line in record.decode("utf-8").splitlines(keepends=True) if _path(line) != sbom]
    newline: Final[str] = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    # a last row without its line end would take the SBOM's row onto its own line
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += newline
    # the row of RECORD itself stays last
    at: Final[int] = next((index for index, line in enumerate(lines) if _path(line) == name), len(lines))
    # installer's helper hashes as it copies; the copy is thrown away
    digest, size = copyfileobj_with_hashing(BytesIO(content), BytesIO(), "sha256")
    row: Final[StringIO] = StringIO()
    csv.writer(row, lineterminator=newline).writerow(RecordEntry(sbom, Hash("sha256", digest), size).to_row())
    lines.insert(at, row.getvalue())
    return "".join(lines).encode()


def _path(line: str) -> str:
    # RECORD quotes a path that holds a comma, a quote or a line end, so the raw start of a line misses its row
    return next(csv.reader([line]), [""])[0]


def append_member(archive: Path, name: str, content: bytes, epoch: int) -> None:
    with zipfile.ZipFile(archive, "a") as handle:
        if name in handle.namelist():
            msg = f"{archive.name} already holds {name}"
            raise SbomError(msg)
        # deflated at the highest level whatever the other members use, since a zipapp may store them all and the SBOM
        # then adds megabytes; a fixed level, time and attributes keep the bytes the same for one input on every system
        handle.writestr(_entry(name, epoch), content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


__all__ = [
    "append_member",
    "write_sbom",
]
