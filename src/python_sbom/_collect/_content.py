"""Resolve the content provider, from an instance, a module:attribute name or the option, and the files defining it."""

from __future__ import annotations

import inspect
import pkgutil
import sys
from importlib.machinery import PathFinder
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError
from python_sbom._model._content import ContentProvider

if TYPE_CHECKING:
    from python_sbom._model._inputs import Settings


def resolve_provider(
    given: ContentProvider | str | None, settings: Settings, root: Path
) -> tuple[ContentProvider, tuple[PurePosixPath, ...]]:
    # an instance wins, as a hook subclass builds one; a module:attribute string overrides the option, as the CLI's flag
    # does; otherwise the content-provider option, or the provider that adds nothing
    if isinstance(given, ContentProvider):
        provider = given
    elif (spec := settings.content_provider if given is None else given) is None:
        provider = ContentProvider()
    else:
        provider = _load(spec, root)
    return provider, _provider_scripts(provider, root)


def _load(spec: str, root: Path) -> ContentProvider:
    # resolve_name also takes a bare module, which is no provider
    module_name, _, attribute = spec.partition(":")
    if not (module_name and attribute):
        msg = f"content provider {spec!r} must be `module:attribute`"
        raise SbomError(msg)
    # the import cache is per process, so a hatch build of a second project, or a test suite building copies of one,
    # would get the provider module the first project imported; the outermost module the project provides that the
    # cache holds from elsewhere is dropped with its submodules, so the project's own copy loads, while a provider built
    # earlier keeps the module objects it already references
    if (other := _imported_elsewhere(module_name, root)) is not None:
        for cached in [name for name in sys.modules if name == other or name.startswith(f"{other}.")]:
            del sys.modules[cached]
    sys.path.insert(0, str(root))
    try:
        provider = pkgutil.resolve_name(spec)
    # ValueError: a name resolve_name cannot parse, such as a second colon
    except (ImportError, AttributeError, ValueError) as error:
        msg = f"content provider {spec!r} does not load from {root}: {error}"
        raise SbomError(msg) from error
    finally:
        sys.path.remove(str(root))
    if isinstance(provider, type) and issubclass(provider, ContentProvider):
        provider = provider()
    if not isinstance(provider, ContentProvider):
        msg = f"content provider {spec!r} is not a ContentProvider subclass or instance"
        raise SbomError(msg)
    return provider


def _imported_elsewhere(module_name: str, root: Path) -> str | None:
    # each package on the way down to the module, and the module itself, that the project provides is compared with what
    # is already imported under its name; namespace packages merge, so only modules and regular packages can clash
    search: list[str] | None = [str(root)]
    parts: Final[list[str]] = module_name.split(".")
    for depth in range(1, len(parts) + 1):
        if search is None or (found := PathFinder.find_spec(".".join(parts[:depth]), search)) is None:
            return None
        imported = getattr(sys.modules.get(found.name), "__file__", None)
        if (
            found.origin is not None
            and imported is not None
            and Path(imported).resolve() != Path(found.origin).resolve()
        ):
            return found.name
        search = None if found.submodule_search_locations is None else list(found.submodule_search_locations)
    return None


def _provider_scripts(provider: ContentProvider, root: Path) -> tuple[PurePosixPath, ...]:
    # each class of the provider defined in the project shapes the document, a base class or mixin as much as the class
    # itself, so the SBOM lists their modules among the build tools; python-sbom's own ContentProvider adds nothing
    found: Final[dict[PurePosixPath, None]] = {}
    for cls in type(provider).__mro__:
        if cls in {ContentProvider, object}:
            continue
        if (source := _source(cls)) is None:
            continue
        resolved, base = Path(source).resolve(), root.resolve()
        if resolved.is_relative_to(base):
            found[PurePosixPath(resolved.relative_to(base).as_posix())] = None
    return tuple(found)


def _source(cls: type) -> str | None:
    # a method's code names the file even for a module hatchling loaded outside the import system, such as a custom
    # hook script
    methods = (
        function.__code__.co_filename
        for _, function in inspect.getmembers(cls, inspect.isfunction)
        if function.__qualname__.startswith(f"{cls.__qualname__}.")
    )
    return next(methods, getattr(sys.modules.get(cls.__module__), "__file__", None))


__all__ = [
    "resolve_provider",
]
