"""A build backend that wraps another one and writes the SBOM into every wheel it builds."""

from __future__ import annotations

import importlib
from functools import cache, reduce
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from ._collect import REVISION_FILE, default_revision, revision_record, settings_from_pyproject
from ._errors import SbomError

if TYPE_CHECKING:
    from collections.abc import Mapping

    #: the settings a frontend passes each hook, such as ``--config-settings`` of pip and build
    ConfigSettings = Mapping[str, str | list[str]] | None

# the hooks PEP 517 and PEP 660 let a backend leave out, which a frontend then replaces with its own default
_OPTIONAL_HOOKS: Final[frozenset[str]] = frozenset({
    "build_editable",
    "get_requires_for_build_editable",
    "get_requires_for_build_sdist",
    "get_requires_for_build_wheel",
    "prepare_metadata_for_build_editable",
    "prepare_metadata_for_build_wheel",
})


class _Hook(Protocol):
    # every optional hook takes directories and the frontend's settings, and returns a file name or requirements
    def __call__(self, *arguments: str | ConfigSettings) -> str | list[str]: ...


class _Backend(Protocol):
    def build_wheel(
        self, wheel_directory: str, config_settings: ConfigSettings = None, metadata_directory: str | None = None, /
    ) -> str: ...

    def build_sdist(self, sdist_directory: str, config_settings: ConfigSettings = None, /) -> str: ...


def build_wheel(
    wheel_directory: str, config_settings: ConfigSettings = None, metadata_directory: str | None = None
) -> str:
    """
    Build a wheel with the wrapped backend, then write the SBOM into it.

    :param wheel_directory: where the wheel goes
    :param config_settings: the frontend's settings, passed on unchanged
    :param metadata_directory: the ``.dist-info`` an earlier ``prepare_metadata_for_build_wheel`` call wrote
    :returns: the wheel's file name

    """
    from ._generate import embed_built  # ruff: ignore[import-outside-top-level] # sdist builds skip it

    root = Path.cwd()
    # read before the backend writes into the checkout, which may not ignore its build directory
    revision = default_revision(root)
    name = _wrapped().build_wheel(wheel_directory, config_settings, metadata_directory)
    embed_built(Path(wheel_directory) / name, root, revision)
    return name


def _wrapped() -> _Backend:
    return _load(Path.cwd())


def build_sdist(sdist_directory: str, config_settings: ConfigSettings = None) -> str:
    """
    Build an sdist with the wrapped backend, then record the source revision in it.

    :param sdist_directory: where the sdist goes
    :param config_settings: the frontend's settings, passed on unchanged
    :returns: the sdist's file name

    """
    from ._wheel import add_to_sdist  # ruff: ignore[import-outside-top-level] # wheel builds skip it

    revision = default_revision(Path.cwd())
    name = _wrapped().build_sdist(sdist_directory, config_settings)
    if (record := revision_record(revision)) is not None:
        add_to_sdist(Path(sdist_directory) / name, REVISION_FILE, record)
    return name


def __getattr__(name: str) -> _Hook:
    # a frontend asks with hasattr whether an optional hook exists, so one the wrapped backend lacks must not exist here
    if name in _OPTIONAL_HOOKS and hasattr(backend := _wrapped(), name):
        return cast("_Hook", getattr(backend, name))
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


@cache
def _load(root: Path) -> _Backend:
    # PEP 517 runs every hook from the project directory, which holds the pyproject.toml naming the backend
    if (reference := settings_from_pyproject(root).build_backend) is None:
        msg = (
            f"{root / 'pyproject.toml'} sets build-backend = 'python_sbom.backend' but names no backend to wrap; set"
            " build-backend in [tool.python-sbom], such as 'mesonpy'"
        )
        raise SbomError(msg)
    module, _, attribute = reference.partition(":")
    if module == __name__:
        msg = f"[tool.python-sbom] build-backend names {reference}, which would wrap itself"
        raise SbomError(msg)
    loaded = importlib.import_module(module)
    # PEP 517 requires every backend to define the two mandatory hooks
    return cast("_Backend", reduce(getattr, attribute.split("."), loaded) if attribute else loaded)


__all__ = [
    "ConfigSettings",
    "build_sdist",
    "build_wheel",
]
