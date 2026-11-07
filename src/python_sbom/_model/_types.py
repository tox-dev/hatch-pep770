from __future__ import annotations

from typing import NotRequired, TypedDict


class OrganizationalEntity(TypedDict):
    """
    An organization that supplies or makes a component.

    :ivar name: the organization's name
    :ivar url: the organization's web sites

    """

    name: str
    url: list[str]


class Contact(TypedDict):
    name: NotRequired[str]
    email: NotRequired[str]


class _Hash(TypedDict):
    alg: str
    content: str


class Property(TypedDict):
    """
    A name and value pair attached to a component or the document.

    :ivar name: the property's name; names this package writes start with the project name or ``python:``
    :ivar value: the property's value

    """

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
    """
    One license entry: either a license by SPDX id or name, or an SPDX expression.

    :ivar license: the license, by ``id`` or ``name``
    :ivar expression: an SPDX license expression
    :ivar acknowledgement: ``declared`` or ``concluded``, for an expression

    """

    license: NotRequired[LicenseInfo]
    expression: NotRequired[str]
    acknowledgement: NotRequired[str]


class _Method(TypedDict):
    technique: str
    confidence: int
    value: str


class Identity(TypedDict):
    field: str
    confidence: int
    methods: list[_Method]


class _Evidence(TypedDict):
    identity: list[Identity]


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
    """
    The components one component depends on.

    :ivar ref: the ``bom-ref`` of the dependent component
    :ivar dependsOn: the ``bom-ref`` values of its dependencies

    """

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
        "inputs": NotRequired[list[_Input]],
    },
)


#: How an artifact was built: one or more workflows, each with its tools, inputs and outputs.
Formula = TypedDict("Formula", {"bom-ref": str, "workflows": list[_Workflow]})


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
    """
    The content of a document, everything but the header :func:`~python_sbom.document` adds.

    :ivar metadata: the document's metadata, with the described component at ``component``
    :ivar components: the components the described component holds or depends on
    :ivar dependencies: the dependency graph, by ``bom-ref``
    :ivar compositions: how complete the inventory is
    :ivar formulation: how the described component was built

    """

    metadata: Metadata
    components: list[Component]
    dependencies: list[Dependency]
    compositions: NotRequired[list[Composition]]
    formulation: NotRequired[list[Formula]]


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
        "formulation": NotRequired[list[Formula]],
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
    "Formula",
    "Identity",
    "License",
    "LicenseInfo",
    "Lifecycle",
    "Metadata",
    "OrganizationalEntity",
    "Property",
    "Tools",
]
