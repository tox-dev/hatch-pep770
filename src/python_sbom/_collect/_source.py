from __future__ import annotations

import hashlib
import zipfile
from email.parser import Parser
from typing import TYPE_CHECKING, Final

from packaging.requirements import InvalidRequirement, Requirement

from python_sbom._errors import WheelError
from python_sbom._model._inputs import BuildScript, BundledWheel, SourceTree
from python_sbom._wheel._archive import find_dist_info, member_sha256, read_metadata_member
from python_sbom._wheel._record import parse_record

if TYPE_CHECKING:
    from email.message import Message
    from pathlib import Path

    from python_sbom._model._inputs import SbomRequest


def read_source_tree(request: SbomRequest) -> SourceTree:
    """
    Read what the document takes from the project tree: the copyright line, the bundled wheels and the build scripts.

    :param request: what the backend knows about the wheel
    :returns: the source tree
    :raises WheelError: when a bundled wheel is malformed

    """
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
            read_bundled_wheel(root, wheel)
            for wheel in sorted(
                {path for pattern in request.settings.bundled_wheels for path in root.glob(pattern)},
                key=lambda path: path.relative_to(root).as_posix(),
            )
        ],
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_scripts=[
            BuildScript(path=script, sha256=hashlib.sha256((root / str(script)).read_bytes()).hexdigest())
            for script in request.build_scripts
        ],
    )


def read_bundled_wheel(root: Path, wheel: Path) -> BundledWheel:
    """
    Read a wheel a project ships as a data file, checking every member against its ``RECORD``.

    :param root: the project directory
    :param wheel: the wheel, under ``root``
    :returns: the wheel's metadata, files and vendored packages
    :raises WheelError: when the wheel lacks metadata, its ``RECORD`` disagrees with its members, or it vendors a
        package without one exact version

    """
    where = wheel.relative_to(root).as_posix()
    with zipfile.ZipFile(wheel) as archive:
        members: Final[list[str]] = sorted(name for name in archive.namelist() if not name.endswith("/"))
        if (dist_info := find_dist_info(members)) is None:
            msg = f"bundled wheel {where} has no .dist-info/METADATA"
            raise WheelError(msg)
        metadata = Parser().parsestr(read_metadata_member(archive, f"{dist_info}/METADATA", where).decode("utf-8"))
        if not (metadata["Name"] and metadata["Version"]):
            msg = f"bundled wheel {where}: {dist_info}/METADATA lacks Name or Version"
            raise WheelError(msg)
        files = parse_record(read_metadata_member(archive, f"{dist_info}/RECORD", where).decode("utf-8"), where)
        _check_record(archive, where, {row.path: row.digest for row in files if row.algorithm == "SHA-256"}, members)
        vendored: Final[list[tuple[str, Message]]] = [
            *_vendor_manifest(archive, where, members),
            *(
                (name, Parser().parsestr(read_metadata_member(archive, name, where).decode("utf-8")))
                for name in members
                if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
            ),
        ]
    return BundledWheel(
        path=where,
        sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        metadata_name=f"{dist_info}/METADATA",
        metadata=metadata,
        files=files,
        vendored=vendored,
    )


def _check_record(archive: zipfile.ZipFile, where: str, digests: dict[str, str], members: list[str]) -> None:
    # the SBOM copies these digests, so a RECORD that misstates the wheel would make the SBOM misstate it too
    unhashed = {member for member in members if not member.endswith(("/RECORD", "/RECORD.jws", "/RECORD.p7s"))}
    if missing := sorted(unhashed - digests.keys()):
        msg = f"bundled wheel {where}: RECORD lacks a SHA-256 for {', '.join(missing)}"
        raise WheelError(msg)
    if extra := sorted(digests.keys() - set(members)):
        msg = f"bundled wheel {where}: RECORD lists {', '.join(extra)}, which the wheel does not hold"
        raise WheelError(msg)
    if changed := [name for name in sorted(digests) if member_sha256(archive, name) != digests[name]]:
        msg = f"bundled wheel {where}: the SHA-256 in RECORD differs from the content of {', '.join(changed)}"
        raise WheelError(msg)


def _vendor_manifest(archive: zipfile.ZipFile, where: str, members: list[str]) -> list[tuple[str, Message]]:
    # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
    found: Final[list[tuple[str, Message]]] = []
    for name in (member for member in members if member.endswith("/_vendor/vendor.txt")):
        for line in read_metadata_member(archive, name, where).decode("utf-8").splitlines():
            if not (text := line.partition("#")[0].strip()):
                continue
            try:
                pins = list((requirement := Requirement(text)).specifier)
            except InvalidRequirement as error:
                msg = f"bundled wheel {where}: vendored requirement in {name} does not parse: {text}"
                raise WheelError(msg) from error
            if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                msg = f"bundled wheel {where}: vendored requirement in {name} pins no one exact version: {text}"
                raise WheelError(msg)
            found.append((name, Parser().parsestr(f"Name: {requirement.name}\nVersion: {pins[0].version}\n")))
    return found


__all__ = [
    "read_bundled_wheel",
    "read_source_tree",
]
