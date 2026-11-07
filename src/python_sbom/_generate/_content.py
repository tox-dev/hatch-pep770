from __future__ import annotations

import importlib
import sys
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._errors import SettingsError
from python_sbom._model._inputs import BundledWheelInfo, Contributions

if TYPE_CHECKING:
    from python_sbom._model._inputs import BundledWheel, SbomRequest


def load_content_provider(spec: str, root: Path) -> tuple[ContentProvider, PurePosixPath | None]:
    """
    Import the content provider a ``content-provider`` option names.

    :param spec: ``module:attribute``, importable from ``root``; the attribute is a :class:`ContentProvider` subclass or
        instance
    :param root: the project directory, searched first for the module
    :returns: the provider, and the module's path relative to ``root`` when it lives there, which the SBOM lists among
        the build tools since it shapes the document
    :raises SettingsError: when the spec is malformed, the import fails, or the attribute is no content provider

    """
    module_name, _, attribute = spec.partition(":")
    if not (module_name and attribute):
        msg = f"content provider {spec!r} must be `module:attribute`"
        raise SettingsError(msg)
    sys.path.insert(0, str(root))
    try:
        module = importlib.import_module(module_name)
    except ImportError as error:
        msg = f"content provider {spec!r} does not import from {root}: {error}"
        raise SettingsError(msg) from error
    finally:
        sys.path.remove(str(root))
    provider = getattr(module, attribute, None)
    if isinstance(provider, type) and issubclass(provider, ContentProvider):
        provider = provider()
    if not isinstance(provider, ContentProvider):
        msg = f"content provider {spec!r} is not a ContentProvider subclass or instance"
        raise SettingsError(msg)
    source = Path(module.__file__ or "").resolve()
    script = (
        PurePosixPath(source.relative_to(root.resolve()).as_posix()) if source.is_relative_to(root.resolve()) else None
    )
    return provider, script


class ContentProvider:
    """
    Adds project-specific content to an SBOM; subclass it and override what the project needs.

    Name a subclass in the ``content-provider`` option, or pass an instance to :func:`build_sbom`.

    """

    def bundled_wheel(self, wheel: BundledWheel) -> BundledWheelInfo:  # ruff: ignore[unused-method-argument, no-self-use] # the no-op default
        """
        Describe what the project does with a wheel it bundles.

        :param wheel: the bundled wheel
        :returns: its extra properties and supplier; none by default

        """
        return BundledWheelInfo(properties=[], supplier=None)

    def contributions(self, request: SbomRequest) -> Contributions:  # ruff: ignore[unused-method-argument, no-self-use] # the no-op default
        """
        Add components, dependencies, root properties or tools, before references and the serial are derived.

        :param request: what the backend knows about the wheel
        :returns: the contributions; none by default

        """
        return Contributions(components=[], dependencies=[], root_properties=[], tools=[])


__all__ = [
    "ContentProvider",
    "load_content_provider",
]
