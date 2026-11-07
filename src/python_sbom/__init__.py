"""SBOMs for Python distributions: write PEP 770 CycloneDX SBOMs into wheels."""

from __future__ import annotations

from ._cli import Options, main
from ._cyclonedx import (
    Body,
    Component,
    Dependency,
    Document,
    OrganizationalEntity,
    Property,
    build_tools,
    component_from_metadata,
    document,
    timestamp,
)
from ._embed import embed
from ._hook import SbomBuildHook
from ._project import BundledWheelProperties, Project, Toml
from ._spdx import Spdx, to_spdx
from ._validate import validate, validate_wheel
from .version import version as __version__

__all__ = [
    "Body",
    "BundledWheelProperties",
    "Component",
    "Dependency",
    "Document",
    "Options",
    "OrganizationalEntity",
    "Project",
    "Property",
    "SbomBuildHook",
    "Spdx",
    "Toml",
    "__version__",
    "build_tools",
    "component_from_metadata",
    "document",
    "embed",
    "main",
    "timestamp",
    "to_spdx",
    "validate",
    "validate_wheel",
]
