from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from email.message import Message

    from ._inputs import Settings


def project_identity(metadata: Message | _core.Metadata, settings: Settings) -> ProjectIdentity:
    prefix, repository, namespace = _core.project_identity(metadata, settings)
    return ProjectIdentity(property_prefix=prefix, repository=repository, serial_namespace=uuid.UUID(namespace))


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
