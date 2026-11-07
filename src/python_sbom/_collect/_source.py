from __future__ import annotations

import hashlib
from pathlib import PurePath
from typing import TYPE_CHECKING

from python_sbom import _core
from python_sbom._errors import SettingsError
from python_sbom._model._inputs import BuildScript, SbomRequest, SourceTree

if TYPE_CHECKING:
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import BundledWheel, Settings


def read_source_tree(request: SbomRequest) -> SourceTree:
    root = request.root
    for pattern in request.settings.bundled_wheels:
        # a wheel outside the project is none the project ships, and pathlib refuses an absolute pattern outright
        if (path := PurePath(pattern)).anchor or ".." in path.parts:
            msg = f"`bundled-wheels` pattern {pattern!r} must be relative to the project, without `..`"
            raise SettingsError(msg)
    return SourceTree(
        copyright=next(
            (
                line
                for license_file in request.metadata.get_all("License-File", None) or []
                if (path := root / license_file).is_file()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.startswith("Copyright")
            ),
            None,
        ),
        # read and verified in parallel by the core
        bundled=_core.read_bundled_wheels([
            (root / relative, relative)
            for relative in sorted({
                wheel.relative_to(root).as_posix()
                for pattern in request.settings.bundled_wheels
                for wheel in root.glob(pattern)
            })
        ]),
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_scripts=[
            BuildScript(path=script, sha256=hashlib.sha256((root / str(script)).read_bytes()).hexdigest())
            for script in request.build_scripts
        ],
    )


def read_bundled_wheel(data: bytes, path: str) -> BundledWheel:
    return _core.read_bundled_wheel(data, path)


def wheel_request(wheel: Path, root: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]) -> SbomRequest:
    return SbomRequest(
        root=root,
        metadata=_core.wheel_metadata(wheel),
        wheel_name=wheel.name,
        settings=settings,
        build_scripts=build_scripts,
    )


__all__ = [
    "read_bundled_wheel",
    "read_source_tree",
    "wheel_request",
]
