from __future__ import annotations

import inspect
import pkgutil
import sys
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SettingsError
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
        raise SettingsError(msg)
    sys.path.insert(0, str(root))
    try:
        provider = pkgutil.resolve_name(spec)
    # ValueError: a name resolve_name cannot parse, such as a second colon
    except (ImportError, AttributeError, ValueError) as error:
        msg = f"content provider {spec!r} does not load from {root}: {error}"
        raise SettingsError(msg) from error
    finally:
        sys.path.remove(str(root))
    if isinstance(provider, type) and issubclass(provider, ContentProvider):
        provider = provider()
    if not isinstance(provider, ContentProvider):
        msg = f"content provider {spec!r} is not a ContentProvider subclass or instance"
        raise SettingsError(msg)
    return provider


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
