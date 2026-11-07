from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

from python_sbom._errors import WheelError

from ._record import record_line

if TYPE_CHECKING:
    from collections.abc import Iterable

# metadata files beyond this size are refused, so a hostile wheel cannot exhaust memory
_METADATA_LIMIT: Final[int] = 16 * 1024 * 1024


def embed_sbom(wheel: Path, name: str, content: bytes, epoch: int) -> str:
    """
    Write an SBOM into a built wheel under ``.dist-info/sboms/``, with its ``RECORD`` row.

    An SBOM of the same name is replaced. Every other entry keeps its name, order, timestamp and attributes; the new
    entry takes ``epoch`` as its timestamp and fixed attributes, so the result is the same on every operating system.
    The wheel keeps its permissions, and a failure leaves it untouched with no temporary file behind.

    :param wheel: the wheel to rewrite in place
    :param name: the SBOM's file name, such as ``project.cdx.json``
    :param content: the SBOM's bytes
    :param epoch: the Unix timestamp of the new entry
    :returns: the SBOM's path inside the wheel
    :raises WheelError: when the archive is not a wheel

    """
    with zipfile.ZipFile(wheel) as archive:
        entries: Final[list[tuple[zipfile.ZipInfo, bytes]]] = [
            (info, archive.read(info)) for info in archive.infolist()
        ]
    if (dist_info := find_dist_info(info.filename for info, _ in entries)) is None:
        msg = f"{wheel} has no .dist-info/METADATA, so it is not a wheel"
        raise WheelError(msg)
    record: Final[str] = f"{dist_info}/RECORD"
    if record not in {info.filename for info, _ in entries}:
        msg = f"{wheel} has no {record}"
        raise WheelError(msg)
    sbom: Final[str] = f"{dist_info}/sboms/{name}"
    lines: Final[list[str]] = [
        line
        for info, data in entries
        if info.filename == record
        for line in data.decode("utf-8").splitlines(keepends=True)
        if not line.startswith(f"{sbom},")
    ]
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    # the row of RECORD itself stays last
    at = next((index for index, line in enumerate(lines) if line.startswith(f"{record},")), len(lines))
    lines.insert(at, f"{record_line(sbom, content)}{newline}")
    # zip timestamps start at 1980
    entry = zipfile.ZipInfo(sbom, time.gmtime(max(epoch, 315532800))[:6])
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3  # Unix, whichever system writes the entry, so the bytes match across operating systems
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    # the SBOM goes right before RECORD, which stays the last entry
    members: Final[list[tuple[zipfile.ZipInfo, bytes]]] = []
    for info, data in entries:
        if info.filename == record:
            members.extend([(entry, content), (info, "".join(lines).encode())])
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


def find_dist_info(names: Iterable[str]) -> str | None:
    return next(
        (name.split("/")[0] for name in names if name.count("/") == 1 and name.endswith(".dist-info/METADATA")),
        None,
    )


def read_metadata_member(archive: zipfile.ZipFile, name: str, where: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        msg = f"{where} has no {name}"
        raise WheelError(msg) from error
    if info.file_size > _METADATA_LIMIT:
        msg = f"{where}: {name} is {info.file_size} bytes, over the {_METADATA_LIMIT} byte limit"
        raise WheelError(msg)
    return archive.read(info)


def member_sha256(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as member:
        for chunk in iter(lambda: member.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "embed_sbom",
    "find_dist_info",
    "member_sha256",
    "read_metadata_member",
]
