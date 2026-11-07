from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from packaging.utils import canonicalize_name

from ._components import project_urls, reference_type

if TYPE_CHECKING:
    from email.message import Message

    from ._inputs import BuildFacts, Settings
    from ._types import Body, Component, Document, Formula


def project_identity(metadata: Message, settings: Settings) -> ProjectIdentity:
    """
    Name a project the way its documents do, so other documents about it, such as a zipapp's, agree.

    :param metadata: the project's core metadata
    :param settings: the project's options, whose ``repository`` wins over the project URLs
    :returns: the identity

    """
    namespace = canonicalize_name(metadata["Name"])
    repository = settings.repository or next(
        (url.rstrip("/") for label, url in project_urls(metadata) if reference_type(label) == "vcs"), None
    )
    base = repository or f"https://pypi.org/project/{namespace}"
    return ProjectIdentity(
        namespace=namespace,
        repository=repository,
        serial_namespace=uuid.uuid5(uuid.NAMESPACE_URL, f"{base}/sboms"),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProjectIdentity:
    """
    How documents name a project.

    :param namespace: the normalized project name, which prefixes the properties this package writes
    :param repository: the repository URL, or ``None``
    :param serial_namespace: the UUID namespace of the serial numbers of the project's documents

    """

    namespace: str
    repository: str | None
    serial_namespace: uuid.UUID


def document(body: Body, namespace: uuid.UUID) -> Document:
    """
    Add the CycloneDX 1.6 header to a document body.

    :param body: the metadata, components, dependencies and formulation
    :param namespace: the UUID namespace of the serial number, see :func:`project_identity`
    :returns: the document; its serial number derives from the body, so identical bodies share one

    """
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def formulation(uid: str, name: str, tools: list[Component], output_ref: str, facts: BuildFacts) -> Formula:
    """
    Record how an artifact was built: one workflow with its tools, its output and the build time it read.

    :param uid: the workflow's identifier, such as ``wheel-build``
    :param name: what the workflow does
    :param tools: the build tools it used
    :param output_ref: the ``bom-ref`` of the artifact it produced
    :param facts: the build facts; ``SOURCE_DATE_EPOCH`` is listed as an input only when it set the build time
    :returns: the formula

    """
    workflow: Formula = {
        "bom-ref": f"formula:{uid}",
        "workflows": [
            {
                "bom-ref": f"workflow:{uid}",
                "uid": uid,
                "name": name,
                "taskTypes": ["build"],
                "resourceReferences": [{"ref": tool["bom-ref"]} for tool in tools],
                "outputs": [{"type": "artifact", "resource": {"ref": output_ref}}],
            }
        ],
    }
    if facts.epoch_from_environment:
        workflow["workflows"][0]["inputs"] = [
            {"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": str(facts.epoch)}]}
        ]
    return workflow


def timestamp(facts: BuildFacts) -> str:
    return datetime.fromtimestamp(facts.epoch, tz=UTC).isoformat()


__all__ = [
    "ProjectIdentity",
    "document",
    "formulation",
    "project_identity",
    "timestamp",
]
