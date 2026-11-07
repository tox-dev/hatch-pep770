"""SBOMs for Python distributions: write PEP 770 CycloneDX SBOMs into wheels."""

from __future__ import annotations

from ._cli._main import main
from ._collect._facts import RevisionReader, collect_facts, default_revision, git_revision
from ._collect._settings import Toml, settings_from_pyproject, settings_from_table
from ._collect._source import read_bundled_wheel, read_source_tree
from ._errors import MissingExtraError, SbomError, SettingsError, SourceRevisionError, WheelError
from ._formats._json import dumps
from ._formats._spdx import Spdx, to_spdx
from ._generate._backend import Backend, BuiltWheel, MetadataBackend
from ._generate._content import ContentProvider, load_content_provider
from ._generate._pipeline import Sbom, build_sbom
from ._model._components import bundled_wheel_component, component_from_metadata, file_component_from_bytes, script_tool
from ._model._document import ProjectIdentity, document, formulation, project_identity
from ._model._inputs import (
    BuildFacts,
    BuildScript,
    BundledWheel,
    BundledWheelInfo,
    Contributions,
    InstalledDistribution,
    Interpreter,
    RecordRow,
    Revision,
    SbomRequest,
    Settings,
    SourceTree,
)
from ._model._tools import tool_components
from ._model._types import Body, Component, Dependency, Document, Formula, License, OrganizationalEntity, Property
from ._validate._document import validate
from ._validate._wheel import validate_wheel
from ._wheel._archive import embed_sbom
from .version import __version__

__all__ = [
    "Backend",
    "Body",
    "BuildFacts",
    "BuildScript",
    "BuiltWheel",
    "BundledWheel",
    "BundledWheelInfo",
    "Component",
    "ContentProvider",
    "Contributions",
    "Dependency",
    "Document",
    "Formula",
    "InstalledDistribution",
    "Interpreter",
    "License",
    "MetadataBackend",
    "MissingExtraError",
    "OrganizationalEntity",
    "ProjectIdentity",
    "Property",
    "RecordRow",
    "Revision",
    "RevisionReader",
    "Sbom",
    "SbomError",
    "SbomRequest",
    "Settings",
    "SettingsError",
    "SourceRevisionError",
    "SourceTree",
    "Spdx",
    "Toml",
    "WheelError",
    "__version__",
    "build_sbom",
    "bundled_wheel_component",
    "collect_facts",
    "component_from_metadata",
    "default_revision",
    "document",
    "dumps",
    "embed_sbom",
    "file_component_from_bytes",
    "formulation",
    "git_revision",
    "load_content_provider",
    "main",
    "project_identity",
    "read_bundled_wheel",
    "read_source_tree",
    "script_tool",
    "settings_from_pyproject",
    "settings_from_table",
    "to_spdx",
    "tool_components",
    "validate",
    "validate_wheel",
]
