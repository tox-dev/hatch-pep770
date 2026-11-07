"""SBOMs for Python distributions: write PEP 770 CycloneDX SBOMs into wheels."""

from __future__ import annotations

from ._backend import Backend
from ._cli._parser import Options, main
from ._collect._facts import BuildFacts, RevisionReader, git_revision
from ._collect._settings import Settings, Toml
from ._errors import SbomError, SettingsError, SourceRevisionError, WheelError
from ._extension import ContentProvider
from ._formats._json import dumps
from ._formats._spdx import Spdx, to_spdx
from ._model._components import component_from_metadata, document
from ._model._types import Body, Component, Dependency, Document, OrganizationalEntity, Property
from ._validate._checks import validate, validate_wheel
from ._wheel._embed import BuiltWheel
from .version import version as __version__

__all__ = [
    "Backend",
    "Body",
    "BuildFacts",
    "BuiltWheel",
    "Component",
    "ContentProvider",
    "Dependency",
    "Document",
    "Options",
    "OrganizationalEntity",
    "Property",
    "RevisionReader",
    "SbomError",
    "Settings",
    "SettingsError",
    "SourceRevisionError",
    "Spdx",
    "Toml",
    "WheelError",
    "__version__",
    "component_from_metadata",
    "document",
    "dumps",
    "git_revision",
    "main",
    "to_spdx",
    "validate",
    "validate_wheel",
]
