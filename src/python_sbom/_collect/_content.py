from __future__ import annotations

import inspect
import pkgutil
import sys
from pathlib import Path, PurePosixPath

from python_sbom._errors import SettingsError
from python_sbom._model._content import ContentProvider


def load_content_provider(spec: str | None, root: Path) -> ContentProvider:
    if spec is None:
        return ContentProvider()
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


def provider_script(provider: ContentProvider, root: Path) -> PurePosixPath | None:
    # a provider defined in the project shapes the document, so the SBOM lists its module among the build tools a
    # method's code names the file even for a module hatchling loaded outside the import system, such as a custom hook
    # script
    cls = type(provider)
    methods = (
        function.__code__.co_filename
        for _, function in inspect.getmembers(cls, inspect.isfunction)
        if function.__qualname__.startswith(f"{cls.__qualname__}.")
    )
    if (source := next(methods, getattr(sys.modules.get(cls.__module__), "__file__", None))) is None:
        return None
    resolved, base = Path(source).resolve(), root.resolve()
    return PurePosixPath(resolved.relative_to(base).as_posix()) if resolved.is_relative_to(base) else None


__all__ = [
    "load_content_provider",
    "provider_script",
]
