"""SBOMs for Python distributions: write PEP 770 CycloneDX SBOMs into wheels."""

from __future__ import annotations

from ._errors import SbomError
from ._model._content import ContentProvider, ProviderContext
from ._model._identity import ProjectIdentity
from ._model._inputs import BundledWheelInfo, Contributions, Settings
from ._model._types import (
    Component,
    Contact,
    Dependency,
    Evidence,
    ExternalReference,
    Hash,
    Identity,
    IdentityMethod,
    License,
    LicenseInfo,
    OrganizationalEntity,
    Property,
)
from .version import __version__

__all__ = [
    "BundledWheelInfo",
    "Component",
    "Contact",
    "ContentProvider",
    "Contributions",
    "Dependency",
    "Evidence",
    "ExternalReference",
    "Hash",
    "Identity",
    "IdentityMethod",
    "License",
    "LicenseInfo",
    "OrganizationalEntity",
    "ProjectIdentity",
    "Property",
    "ProviderContext",
    "SbomError",
    "Settings",
    "__version__",
]
