"""The document types exported by python-sbom."""

from __future__ import annotations

from ._content import BundledWheelInfo, ContentProvider, Contributions, ProviderContext
from ._identity import ProjectIdentity
from ._inputs import Revision, Settings
from ._types import (
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
    "Revision",
    "Settings",
]
