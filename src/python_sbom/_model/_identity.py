"""Decide how a project's SBOMs name it: its property prefix, its repository URL and the namespace of their serials."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._iri import iri_reference
from ._names import property_prefix, reference_type

if TYPE_CHECKING:
    from ._inputs import Settings
    from ._metadata import CoreMetadata


def project_identity(metadata: CoreMetadata, settings: Settings) -> ProjectIdentity:
    project = property_prefix(metadata.name)
    repository = settings.repository
    # links into the repository extend its URL, so one that cannot be an IRI reference, as an scp-style git address, is
    # passed over for the next
    for label, url in [] if repository else metadata.project_urls():
        if reference_type(label) == "vcs" and (link := iri_reference(url)) is not None:
            repository = link.rstrip("/")
            break
    base = repository or f"https://pypi.org/project/{project}"
    return ProjectIdentity(
        property_prefix=project,
        repository=repository,
        serial_namespace=uuid.uuid5(uuid.NAMESPACE_URL, f"{base}/sboms"),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProjectIdentity:
    """
    How every SBOM of a project names it.

    :param property_prefix: the project's normalized name, which starts the names of the properties python-sbom writes,
        such as ``virtualenv`` in ``virtualenv:bundled-wheel``
    :param repository: the repository URL, from the options or the first ``Source``, ``Repository`` or ``GitHub``
        project URL, or ``None``
    :param serial_namespace: the UUID namespace of the serial numbers of the project's SBOMs

    """

    property_prefix: str
    repository: str | None
    serial_namespace: uuid.UUID


__all__ = [
    "ProjectIdentity",
    "project_identity",
]
