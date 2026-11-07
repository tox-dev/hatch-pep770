from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from typing import TYPE_CHECKING, Final

from packaging.requirements import InvalidRequirement, Requirement

from python_sbom._errors import WheelError

if TYPE_CHECKING:
    from email.message import Message
    from pathlib import Path, PurePosixPath

    from python_sbom._extension import ContentProvider
    from python_sbom._model._types import Property

    from ._settings import Settings


@dataclass(frozen=True, slots=True, kw_only=True)
class BundledWheel:
    # A wheel the project ships as a data file, read from the project tree.
    path: str
    sha256: str
    metadata_name: str
    metadata: Message
    record: str
    vendored: list[tuple[str, Message]]
    extra_properties: list[Property]


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildScript:
    # A build script that shapes the document, so a rebuild has to match it.
    path: PurePosixPath
    sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceTree:
    # What the document takes from the project tree besides the wheel's metadata.
    copyright: str | None
    bundled: list[BundledWheel]
    build_script: BuildScript | None


def read_source_tree(
    root: Path,
    settings: Settings,
    license_files: list[str],
    build_script: PurePosixPath | None,
    content: ContentProvider,
) -> SourceTree:
    return SourceTree(
        copyright=next(
            (
                line
                for license_file in license_files
                if (path := root / license_file).is_file()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.startswith("Copyright")
            ),
            None,
        ),
        bundled=[
            _read_bundled_wheel(root, wheel, content)
            for wheel in sorted(
                {path for pattern in settings.bundled_wheels for path in root.glob(pattern)},
                key=lambda path: path.relative_to(root).as_posix(),
            )
        ],
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_script=None
        if build_script is None
        else BuildScript(path=build_script, sha256=hashlib.sha256((root / str(build_script)).read_bytes()).hexdigest()),
    )


def _read_bundled_wheel(root: Path, wheel: Path, content: ContentProvider) -> BundledWheel:
    with zipfile.ZipFile(wheel) as archive:
        members: Final[list[str]] = sorted(archive.namelist())
        if (
            metadata_name := next(
                (name for name in members if name.count("/") == 1 and name.endswith(".dist-info/METADATA")), None
            )
        ) is None:
            msg = f"bundled wheel {wheel} has no .dist-info/METADATA"
            raise WheelError(msg)
        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        record = archive.read(metadata_name.replace("METADATA", "RECORD")).decode("utf-8")
        vendored: Final[list[tuple[str, Message]]] = [
            *_vendor_manifest(wheel, archive, members),
            *(
                (name, Parser().parsestr(archive.read(name).decode("utf-8")))
                for name in members
                if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
            ),
        ]
    return BundledWheel(
        path=wheel.relative_to(root).as_posix(),
        sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        metadata_name=metadata_name,
        metadata=metadata,
        record=record,
        vendored=vendored,
        extra_properties=content.bundled_wheel_properties(wheel),
    )


def _vendor_manifest(wheel: Path, archive: zipfile.ZipFile, members: list[str]) -> list[tuple[str, Message]]:
    # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
    found: Final[list[tuple[str, Message]]] = []
    for name in members:
        if not name.endswith("/_vendor/vendor.txt"):
            continue
        for line in archive.read(name).decode("utf-8").splitlines():
            if not (requirement := line.partition("#")[0].strip()):
                continue
            try:
                pins = list((parsed := Requirement(requirement)).specifier)
            except InvalidRequirement as error:
                msg = f"vendored requirement in {wheel.name}:{name} does not parse: {requirement}"
                raise WheelError(msg) from error
            if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                msg = f"Unpinned vendored dependency in {wheel.name}:{name}: {requirement}; pin one exact version"
                raise WheelError(msg)
            found.append((name, Parser().parsestr(f"Name: {parsed.name}\nVersion: {pins[0].version}\n")))
    return found


__all__ = [
    "BuildScript",
    "BundledWheel",
    "SourceTree",
    "read_source_tree",
]
