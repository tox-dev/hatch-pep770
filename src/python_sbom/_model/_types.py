from __future__ import annotations

from typing import NotRequired, TypedDict


class OrganizationalEntity(TypedDict):
    """An organization that supplies or makes a component."""

    name: str
    url: list[str]


class Contact(TypedDict):
    name: NotRequired[str]
    email: NotRequired[str]


class _Hash(TypedDict):
    alg: str
    content: str


class Property(TypedDict):
    """A name and value pair; names this package writes start with the project name or ``python:``."""

    name: str
    value: str


class ExternalReference(TypedDict):
    type: str
    url: str
    comment: NotRequired[str]


class LicenseInfo(TypedDict):
    id: NotRequired[str]
    name: NotRequired[str]
    acknowledgement: str


class License(TypedDict):
    license: NotRequired[LicenseInfo]
    expression: NotRequired[str]
    acknowledgement: NotRequired[str]


class _Method(TypedDict):
    technique: str
    confidence: int
    value: str


class _Identity(TypedDict):
    field: str
    confidence: int
    methods: list[_Method]


class _Evidence(TypedDict):
    identity: list[_Identity]


#: A CycloneDX component: a distribution, an application, the interpreter or a file.
Component = TypedDict(
    "Component",
    {
        "type": str,
        "bom-ref": str,
        "name": str,
        "version": NotRequired[str],
        "purl": NotRequired[str],
        "supplier": NotRequired[OrganizationalEntity],
        "authors": NotRequired[list[Contact]],
        "description": NotRequired[str],
        "licenses": NotRequired[list[License]],
        "copyright": NotRequired[str],
        "hashes": NotRequired[list[_Hash]],
        "externalReferences": NotRequired[list[ExternalReference]],
        "properties": NotRequired[list[Property]],
        "evidence": NotRequired[_Evidence],
        "components": NotRequired[list["Component"]],
    },
)


class Dependency(TypedDict):
    """The components one component depends on, by ``bom-ref``."""

    ref: str
    dependsOn: NotRequired[list[str]]


class _Reference(TypedDict):
    ref: str


class _Output(TypedDict):
    type: str
    resource: _Reference


class _Input(TypedDict):
    environmentVars: list[Property]


_Workflow = TypedDict(
    "_Workflow",
    {
        "bom-ref": str,
        "uid": str,
        "name": str,
        "taskTypes": list[str],
        "resourceReferences": list[_Reference],
        "outputs": list[_Output],
        "inputs": list[_Input],
    },
)


_Formula = TypedDict("_Formula", {"bom-ref": str, "workflows": list[_Workflow]})


class Lifecycle(TypedDict):
    phase: str


class Tools(TypedDict):
    components: list[Component]


class Metadata(TypedDict):
    timestamp: str
    lifecycles: list[Lifecycle]
    tools: Tools
    manufacturer: NotRequired[OrganizationalEntity]
    authors: NotRequired[list[Contact]]
    supplier: NotRequired[OrganizationalEntity]
    component: Component
    licenses: NotRequired[list[License]]
    properties: NotRequired[list[Property]]


class Composition(TypedDict):
    aggregate: str
    dependencies: list[str]


class Body(TypedDict):
    """The content of a document, everything but the header :func:`document` adds."""

    metadata: Metadata
    components: list[Component]
    dependencies: list[Dependency]
    compositions: NotRequired[list[Composition]]
    formulation: NotRequired[list[_Formula]]


#: A complete CycloneDX 1.6 JSON document.
Document = TypedDict(
    "Document",
    {
        "$schema": str,
        "bomFormat": str,
        "specVersion": str,
        "serialNumber": str,
        "version": int,
        "metadata": Metadata,
        "components": list[Component],
        "dependencies": list[Dependency],
        "compositions": NotRequired[list[Composition]],
        "formulation": NotRequired[list[_Formula]],
    },
)


__all__ = [
    "Body",
    "Component",
    "Composition",
    "Contact",
    "Dependency",
    "Document",
    "ExternalReference",
    "License",
    "LicenseInfo",
    "Lifecycle",
    "Metadata",
    "OrganizationalEntity",
    "Property",
    "Tools",
]
