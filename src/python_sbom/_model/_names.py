"""The names python-sbom derives: SBOM file names, property names, purls and reference types."""

from __future__ import annotations

import re
from typing import Final

from packageurl import PackageURL
from packaging.utils import canonicalize_name

#: the metadata property in which a document names its own file; validation checks such documents in full
SBOM_FILE: Final[str] = "sbom:file"
#: the metadata property in which a document names the project's repository
SBOM_REPOSITORY: Final[str] = "sbom:repository"
# the label normalization and mapping cyclonedx-py applies to Project-URL entries, so the same metadata yields the same
# reference types whichever generator produced the document, plus the well-known labels of PEP 753 it lacks; funding
# labels have no CycloneDX type and fall to "other"
_URL_LABEL_TO_REFERENCE_TYPE: Final[dict[str, str]] = {
    "bugtracker": "issue-tracker",
    "issuetracker": "issue-tracker",
    "issues": "issue-tracker",
    "issue": "issue-tracker",
    "bugs": "issue-tracker",
    "bugreports": "issue-tracker",
    "tracker": "issue-tracker",
    "home": "website",
    "homepage": "website",
    "download": "distribution",
    "documentation": "documentation",
    "docs": "documentation",
    "changelog": "release-notes",
    "changes": "release-notes",
    "whatsnew": "release-notes",
    "history": "release-notes",
    "releasenotes": "release-notes",
    "source": "vcs",
    "sourcecode": "vcs",
    "repository": "vcs",
    "github": "vcs",
    "chat": "chat",
}


def sbom_property(project: str, key: str) -> str:
    return f"{project}:{key}"


def sbom_file_name(name: str) -> str:
    return f"{property_prefix(name)}.cdx.json"


def property_prefix(name: str) -> str:
    # the normalized project name, which prefixes the properties this package writes
    return canonicalize_name(name)


def archive_sbom_file_name(archive: str) -> str:
    # next to the archive, and inside it when embedded, where reading the archive again must skip it
    return f"{archive}.cdx.json"


def purl(name: str, version: str | None = None) -> str:
    # normalized as PEP 503 does, so every spelling of a project, jaraco.context or jaraco_context, gets one purl and a
    # component's bom-ref agrees with its purl; packageurl only lowercases and turns underscores into dashes
    return PackageURL(type="pypi", name=canonicalize_name(name), version=version).to_string()


def pypi_url(name: str, version: str | None = None) -> str:
    return f"https://pypi.org/project/{name}/{version}/" if version else f"https://pypi.org/project/{name}/"


def tool_ref(ref: str) -> str:
    # prefixed because the same distribution can be both a build tool and a component of the artifact
    return f"tool:{ref}"


_REFERENCE_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-z]")


def reference_type(label: str) -> str:
    return _URL_LABEL_TO_REFERENCE_TYPE.get(_REFERENCE_TYPE_PATTERN.sub("", label.lower()), "other")


__all__ = [
    "SBOM_FILE",
    "SBOM_REPOSITORY",
    "archive_sbom_file_name",
    "property_prefix",
    "purl",
    "pypi_url",
    "reference_type",
    "sbom_file_name",
    "sbom_property",
    "tool_ref",
]
