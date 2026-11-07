from __future__ import annotations

import hashlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePath
from typing import TYPE_CHECKING, Final

from installer.records import InvalidRecordEntry, parse_record_file
from installer.sources import WheelFile
from packaging.requirements import InvalidRequirement, Requirement

from python_sbom._errors import SbomError
from python_sbom._model._inputs import BuildScript, BundledWheel, RecordRow, SbomRequest, SourceTree
from python_sbom._model._metadata import CoreMetadata, parse_metadata
from python_sbom._wheel._archive import open_archive, read_member, read_wheel_metadata
from python_sbom._wheel._record import record_rows

if TYPE_CHECKING:
    import zipfile
    from collections.abc import Callable
    from pathlib import Path, PurePosixPath
    from typing import IO

    from python_sbom._model._inputs import Settings

# a bundled wheel is hashed in chunks of this size
_CHUNK: Final[int] = 1024 * 1024
# wheels verified at once, each perhaps in memory whole
_WORKERS: Final[int] = 4


def read_source_tree(request: SbomRequest) -> SourceTree:
    root = request.root
    wheels: Final[set[str]] = set()
    for pattern in request.settings.bundled_wheels:
        # a wheel outside the project is none the project ships, and pathlib refuses an absolute pattern outright
        if (path := PurePath(pattern)).anchor or ".." in path.parts:
            msg = f"`bundled-wheels` pattern {pattern!r} must be relative to the project, without `..`"
            raise SbomError(msg)
        wheels.update(wheel.relative_to(root).as_posix() for wheel in root.glob(pattern))
    return SourceTree(
        copyright=copyright_notice(root, request.metadata.values("license_files")),
        bundled=read_bundled_wheels(sorted(wheels), lambda path: (root / path).open("rb")),
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_scripts=[
            BuildScript(path=script, sha256=hashlib.sha256((root / str(script)).read_bytes()).hexdigest())
            for script in request.build_scripts
        ],
    )


def copyright_notice(root: Path, license_files: list[str]) -> str | None:
    # the first Copyright line of the license files the project names, as they sit in the project
    for license_file in license_files:
        if (path := root / license_file).is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("Copyright"):
                    return line
    return None


def read_bundled_wheels(paths: list[str], open_wheel: Callable[[str], IO[bytes]]) -> list[BundledWheel]:
    # inflating and hashing release the GIL, so the wheels verify side by side, a few at a time, as each may be held in
    # memory whole; results and the first error come in the order given
    def read(path: str) -> BundledWheel:
        with open_wheel(path) as stream:
            return _read_bundled_wheel(stream, path)

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        return list(pool.map(read, paths))


def _read_bundled_wheel(stream: IO[bytes], path: str) -> BundledWheel:
    where: Final[str] = f"bundled wheel {path}"
    digest: Final = hashlib.sha256()
    while chunk := stream.read(_CHUNK):
        digest.update(chunk)
    stream.seek(0)
    with open_archive(stream, where) as archive:
        # installer takes the project name from the archive's file name, which an archive read from memory lacks
        archive.filename = path
        members: Final[list[str]] = sorted(name for name in archive.namelist() if not name.endswith("/"))
        wheel, metadata = read_wheel_metadata(archive, where)
        dist_info: Final[str] = wheel.dist_info_dir
        _check_named(metadata, where, f"{dist_info}/METADATA")
        files: Final[list[RecordRow]] = _verified_record(archive, wheel, where)
        vendored: Final[list[tuple[str, CoreMetadata]]] = [
            *_vendor_manifest(archive, where, members),
            *(
                (name, _vendored_metadata(archive, where, name))
                for name in members
                if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
            ),
        ]
    return BundledWheel(
        path=path,
        sha256=digest.hexdigest(),
        metadata_name=f"{dist_info}/METADATA",
        metadata=metadata,
        files=files,
        vendored=vendored,
    )


def _check_named(metadata: CoreMetadata, where: str, name: str) -> None:
    if not (metadata.name and metadata.version):
        msg = f"{where}: {name} lacks Name or Version"
        raise SbomError(msg)


def _verified_record(archive: zipfile.ZipFile, wheel: WheelFile, where: str) -> list[RecordRow]:
    # the SBOM copies these rows, so a RECORD that misstates the wheel would make the SBOM misstate it too
    dist_info: Final[str] = wheel.dist_info_dir
    # installer decompresses RECORD whole, so a capped read comes first and bounds installer's read of the same bytes
    record: Final[str] = read_member(archive, f"{dist_info}/RECORD", where).decode("utf-8")
    try:
        rows: Final[list[tuple[str, str, str]]] = list(parse_record_file(record.splitlines()))
        # read before installer's check, which takes any hashlib name and fails on one needing a length, such as
        # shake_128, with a TypeError
        found: Final[list[RecordRow]] = record_rows(rows, where)
    except InvalidRecordEntry as error:
        msg = f"{where}: RECORD does not parse: {error}"
        raise SbomError(msg) from error
    # installer checks the last row of a path only, skips rows naming no member, and lets a RECORD.jws or RECORD.p7s
    # anywhere under the .dist-info, "../" included, go unlisted, so each of these checks is ours
    if repeated := sorted(path for path, count in Counter(path for path, _, _ in rows).items() if count > 1):
        msg = f"{where}: RECORD lists {', '.join(repeated)} more than once"
        raise SbomError(msg)
    members: Final[set[str]] = {info.filename for info in archive.infolist() if not info.is_dir()}
    recorded: Final[set[str]] = {path for path, _, _ in rows}
    # installer checks the row of RECORD itself, the one row without a digest
    if missing := sorted(
        members - recorded - {f"{dist_info}/{name}" for name in ("RECORD", "RECORD.jws", "RECORD.p7s")}
    ):
        msg = f"{where}: RECORD lacks a digest for {', '.join(missing)}"
        raise SbomError(msg)
    if extra := sorted(recorded - members):
        msg = f"{where}: RECORD lists {', '.join(extra)}, which the wheel does not hold"
        raise SbomError(msg)
    try:
        wheel.validate_record()
    except WheelFile.validation_error as error:
        # installer documents the exception class only, not the list of issues it carries
        issues: Final[list[str]] = getattr(error, "issues", [str(error)])
        prefix: Final[str] = f"In {archive.filename}, "
        msg = f"{where}: RECORD disagrees with the wheel: {'; '.join(issue.removeprefix(prefix) for issue in issues)}"
        raise SbomError(msg) from error
    return found


def _vendor_manifest(archive: zipfile.ZipFile, where: str, members: list[str]) -> list[tuple[str, CoreMetadata]]:
    # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
    found: Final[list[tuple[str, CoreMetadata]]] = []
    for name in (member for member in members if member.endswith("/_vendor/vendor.txt")):
        for line in read_member(archive, name, where).decode("utf-8").splitlines():
            if not (text := line.partition("#")[0].strip()):
                continue
            try:
                pins = list((requirement := Requirement(text)).specifier)
            except InvalidRequirement as error:
                msg = f"{where}: vendored requirement in {name} does not parse: {text}"
                raise SbomError(msg) from error
            if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                msg = f"{where}: vendored requirement in {name} pins no one exact version: {text}"
                raise SbomError(msg)
            found.append((name, CoreMetadata(raw={"name": requirement.name, "version": pins[0].version}, unparsed={})))
    return found


def _vendored_metadata(archive: zipfile.ZipFile, where: str, name: str) -> CoreMetadata:
    metadata: Final[CoreMetadata] = parse_metadata(read_member(archive, name, where).decode("utf-8"))
    _check_named(metadata, where, name)
    return metadata


def wheel_request(wheel: Path, root: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]) -> SbomRequest:
    with open_archive(wheel, str(wheel)) as archive:
        _, metadata = read_wheel_metadata(archive, str(wheel))
    return SbomRequest(
        root=root, metadata=metadata, wheel_name=wheel.name, settings=settings, build_scripts=build_scripts
    )


__all__ = [
    "copyright_notice",
    "read_bundled_wheels",
    "read_source_tree",
    "wheel_request",
]
