from __future__ import annotations

import hashlib
import zipfile
import zlib
from collections import Counter
from contextlib import contextmanager
from typing import IO, TYPE_CHECKING, Final

from installer.sources import WheelFile

from python_sbom._errors import SbomError
from python_sbom._model._metadata import CoreMetadata, parse_metadata

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

# metadata files beyond this size are refused, so a hostile wheel cannot exhaust memory
_METADATA_LIMIT: Final[int] = 16 * 1024 * 1024
# members inflate a chunk at a time, so a size the archive states falsely is caught before it is all in memory
CHUNK: Final[int] = 1024 * 1024


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
                raise SbomError(msg)
            yield archive
    # zipfile raises these as late as a member's last read, inside installer's checks too, which let them through
    except (zipfile.BadZipFile, zlib.error) as error:
        msg = f"{where} is not a valid zip archive: {error}"
        raise SbomError(msg) from error


def read_wheel_metadata(archive: zipfile.ZipFile, where: str) -> tuple[WheelFile, CoreMetadata]:
    wheel, dist_info = wheel_source(archive, where)
    # read capped, as installer's read_dist_info decompresses the member whole
    return wheel, parse_metadata(read_member(archive, f"{dist_info}/METADATA", where).decode("utf-8"))


def wheel_source(archive: zipfile.ZipFile, where: str) -> tuple[WheelFile, str]:
    # installer refuses a wheel whose file name does not parse, or that holds other than one top-level .dist-info, since
    # a second one is a decoy that could decide whose metadata counts
    try:
        wheel = WheelFile(archive)
        dist_info = wheel.dist_info_dir
    except ValueError as error:
        msg = f"{where} is not a wheel: {error}"
        raise SbomError(msg) from error
    return wheel, dist_info


def read_member(archive: zipfile.ZipFile, name: str, where: str, limit: int = _METADATA_LIMIT) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        msg = f"{where} has no {name}"
        raise SbomError(msg) from error
    # counted as it decompresses, since the size the archive states may lie and one read decompresses it all at once
    content: Final[bytearray] = bytearray()
    with archive.open(info) as member:
        while chunk := member.read(CHUNK):
            content.extend(chunk)
            if len(content) > limit:
                msg = f"{where}: {name} is over the {limit} byte limit"
                raise SbomError(msg)
    return bytes(content)


def sha256_hex(stream: IO[bytes]) -> str:
    # hashlib.file_digest wants readinto, which a zip member stream typed as IO[bytes] does not promise
    digest: Final = hashlib.sha256()
    while chunk := stream.read(CHUNK):
        digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CHUNK",
    "open_archive",
    "read_member",
    "read_wheel_metadata",
    "sha256_hex",
    "wheel_source",
]
