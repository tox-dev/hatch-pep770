from __future__ import annotations

import hashlib
from collections import Counter
from email.parser import Parser
from io import BytesIO
from typing import TYPE_CHECKING, Final

from packaging.requirements import InvalidRequirement, Requirement

from python_sbom._errors import WheelError
from python_sbom._model._inputs import BuildScript, BundledWheel, SbomRequest, SourceTree
from python_sbom._wheel._archive import member_digest, open_archive, read_member, read_wheel_metadata
from python_sbom._wheel._record import HASHLIB_NAMES, UNHASHED, parse_record

if TYPE_CHECKING:
    import zipfile
    from email.message import Message
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import RecordRow, Settings


def read_source_tree(request: SbomRequest) -> SourceTree:
    root = request.root
    return SourceTree(
        copyright=next(
            (
                line
                for license_file in request.metadata.get_all("License-File", [])
                if (path := root / license_file).is_file()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.startswith("Copyright")
            ),
            None,
        ),
        bundled=[
            read_bundled_wheel((root / relative).read_bytes(), relative)
            for relative in sorted({
                wheel.relative_to(root).as_posix()
                for pattern in request.settings.bundled_wheels
                for wheel in root.glob(pattern)
            })
        ],
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_scripts=[
            BuildScript(path=script, sha256=hashlib.sha256((root / str(script)).read_bytes()).hexdigest())
            for script in request.build_scripts
        ],
    )


def read_bundled_wheel(data: bytes, path: str) -> BundledWheel:
    where: Final[str] = f"bundled wheel {path}"
    with open_archive(BytesIO(data), where) as archive:
        members: Final[list[str]] = sorted(name for name in archive.namelist() if not name.endswith("/"))
        dist_info, metadata = read_wheel_metadata(archive, where)
        _check_named(metadata, where, f"{dist_info}/METADATA")
        files: Final[list[RecordRow]] = _verified_record(archive, where, dist_info)
        vendored: Final[list[tuple[str, Message]]] = [
            *_vendor_manifest(archive, where, members),
            *(
                (name, _vendored_metadata(archive, where, name))
                for name in members
                if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
            ),
        ]
    return BundledWheel(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        metadata_name=f"{dist_info}/METADATA",
        metadata=metadata,
        files=files,
        vendored=vendored,
    )


def _check_named(metadata: Message, where: str, name: str) -> None:
    if not (metadata["Name"] and metadata["Version"]):
        msg = f"{where}: {name} lacks Name or Version"
        raise WheelError(msg)


def _verified_record(archive: zipfile.ZipFile, where: str, dist_info: str) -> list[RecordRow]:
    # the SBOM copies these rows, so a RECORD that misstates the wheel would make the SBOM misstate it too
    rows: Final[list[RecordRow]] = parse_record(
        read_member(archive, f"{dist_info}/RECORD", where).decode("utf-8"), where
    )
    if repeated := sorted(path for path, count in Counter(row.path for row in rows).items() if count > 1):
        msg = f"{where}: RECORD lists {', '.join(repeated)} more than once"
        raise WheelError(msg)
    members: Final[dict[str, zipfile.ZipInfo]] = {
        info.filename: info for info in archive.infolist() if not info.is_dir()
    }
    recorded: Final[set[str]] = {row.path for row in rows}
    if missing := sorted(members.keys() - recorded - {f"{dist_info}/{name}" for name in UNHASHED}):
        msg = f"{where}: RECORD lacks a digest for {', '.join(missing)}"
        raise WheelError(msg)
    if extra := sorted(recorded - members.keys()):
        msg = f"{where}: RECORD lists {', '.join(extra)}, which the wheel does not hold"
        raise WheelError(msg)
    if resized := [row.path for row in rows if row.size != str(members[row.path].file_size)]:
        msg = f"{where}: the size in RECORD differs from the size of {', '.join(resized)}"
        raise WheelError(msg)
    if changed := [
        row.path
        for row in rows
        if member_digest(archive, members[row.path], HASHLIB_NAMES[row.algorithm]) != row.digest
    ]:
        msg = f"{where}: the digest in RECORD differs from the content of {', '.join(changed)}"
        raise WheelError(msg)
    return rows


def _vendor_manifest(archive: zipfile.ZipFile, where: str, members: list[str]) -> list[tuple[str, Message]]:
    # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
    found: Final[list[tuple[str, Message]]] = []
    for name in (member for member in members if member.endswith("/_vendor/vendor.txt")):
        for line in read_member(archive, name, where).decode("utf-8").splitlines():
            if not (text := line.partition("#")[0].strip()):
                continue
            try:
                pins = list((requirement := Requirement(text)).specifier)
            except InvalidRequirement as error:
                msg = f"{where}: vendored requirement in {name} does not parse: {text}"
                raise WheelError(msg) from error
            if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                msg = f"{where}: vendored requirement in {name} pins no one exact version: {text}"
                raise WheelError(msg)
            found.append((name, Parser().parsestr(f"Name: {requirement.name}\nVersion: {pins[0].version}\n")))
    return found


def _vendored_metadata(archive: zipfile.ZipFile, where: str, name: str) -> Message:
    metadata: Final[Message] = Parser().parsestr(read_member(archive, name, where).decode("utf-8"))
    _check_named(metadata, where, name)
    return metadata


def wheel_request(wheel: Path, root: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]) -> SbomRequest:
    with open_archive(wheel, str(wheel)) as archive:
        _, metadata = read_wheel_metadata(archive, str(wheel))
    return SbomRequest(
        root=root, metadata=metadata, wheel_name=wheel.name, settings=settings, build_scripts=build_scripts
    )


__all__ = [
    "read_bundled_wheel",
    "read_source_tree",
    "wheel_request",
]
