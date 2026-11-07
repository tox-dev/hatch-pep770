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
    """
    A person who wrote or maintains a component.

    :ivar name: the person's name
    :ivar email: the person's email address

    """

    name: NotRequired[str]
    email: NotRequired[str]


class Hash(TypedDict):
    """
    A digest of a component's bytes.

    :ivar alg: the algorithm as CycloneDX names it, such as ``SHA-256``
    :ivar content: the digest as lowercase hex

    """

    alg: str
    content: str


class Property(TypedDict):
    """
    A name and value pair attached to a component or the document.

    :ivar name: the property's name; names this package writes start with the project's prefix or ``python:``
    :ivar value: the property's value

    """

    name: str
    value: str


class ExternalReference(TypedDict):
    """
    A link from a component to something about it.

    :ivar type: the CycloneDX reference type, such as ``vcs`` or ``website``
    :ivar url: the link
    :ivar comment: what the link is, such as the Project-URL label it came from

    """

    type: str
    url: str
    comment: NotRequired[str]


class LicenseInfo(TypedDict):
    """
    One license, by SPDX id or by name.

    :ivar id: the SPDX license id
    :ivar name: the license's name, when it has no SPDX id
    :ivar acknowledgement: ``declared`` when the metadata names it, ``concluded`` when python-sbom resolved it

    """

    id: NotRequired[str]
    name: NotRequired[str]
    acknowledgement: str


class License(TypedDict):
    """
    One license entry of a component: a license or an SPDX expression.

    :ivar license: the license, by SPDX id or by name
    :ivar expression: an SPDX license expression
    :ivar acknowledgement: ``declared`` or ``concluded``, for an expression

    """

    license: NotRequired[LicenseInfo]
    expression: NotRequired[str]
    acknowledgement: NotRequired[str]


class IdentityMethod(TypedDict):
    """
    How a component's identity was established.

    :ivar technique: the CycloneDX technique, such as ``manifest-analysis`` or ``hash-comparison``
    :ivar confidence: from 0 to 1
    :ivar value: what the technique read, such as the path of a ``METADATA`` file or a digest

    """

    technique: str
    confidence: int
    value: str


class Identity(TypedDict):
    """
    The evidence for one field of a component's identity.

    :ivar field: the field it supports, such as ``purl`` or ``hash``
    :ivar confidence: from 0 to 1
    :ivar methods: how it was established

    """

    field: str
    confidence: int
    methods: list[IdentityMethod]


class Evidence(TypedDict):
    """
    Why a component is what it says it is.

    :ivar identity: the evidence per field

    """

    identity: list[Identity]


#: A CycloneDX 1.6 component: a distribution, an application, the interpreter or a file, as a dictionary with the
#: keys the CycloneDX component object defines, of which python-sbom uses ``type``, ``bom-ref``, ``name``,
#: ``version``, ``purl``, ``supplier``, ``authors``, ``description``, ``licenses``, ``copyright``, ``hashes``,
#: ``externalReferences``, ``properties``, ``evidence`` and the nested ``components``.
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
        "hashes": NotRequired[list[Hash]],
        "externalReferences": NotRequired[list[ExternalReference]],
        "properties": NotRequired[list[Property]],
        "evidence": NotRequired[Evidence],
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
    metadata: Metadata
    components: list[Component]
    dependencies: list[Dependency]
    compositions: NotRequired[list[Composition]]
    formulation: NotRequired[list[Formula]]


_Header = TypedDict(
    "_Header",
    {"$schema": str, "bomFormat": str, "specVersion": str, "serialNumber": str, "version": int},
)


class Document(Body, _Header):
    pass


__all__ = [
    "Body",
    "Component",
    "Composition",
    "Contact",
    "Dependency",
    "Document",
    "Evidence",
    "ExternalReference",
    "Formula",
    "Hash",
    "Identity",
    "IdentityMethod",
    "License",
    "LicenseInfo",
    "Lifecycle",
    "Metadata",
    "OrganizationalEntity",
    "Property",
    "Tools",
]
