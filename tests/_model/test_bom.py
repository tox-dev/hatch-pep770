from __future__ import annotations

import dataclasses
import json
import uuid
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final, cast

import pytest

from python_sbom import BundledWheelInfo, ContentProvider, Contributions, ProviderContext
from python_sbom._errors import SbomError
from python_sbom._model._bom import (
    check_refs,
    checked_contributions,
    contributed_properties,
    formulation,
    with_header,
)
from python_sbom._model._inputs import BuildScript, BundledWheel, Revision
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from conftest import Describe

    from python_sbom import Component, Dependency, Property
    from python_sbom._model._inputs import BuildFacts, Settings
    from python_sbom._model._types import Body, Formula, OrganizationalEntity

_INTERPRETER: Final[str] = "tool:pkg:generic/cpython@3.15.0"


def test_minimal_document(describe: Describe) -> None:
    document = describe()
    body = {key: value for key, value in document.items() if key not in {"$schema", "bomFormat", "specVersion"}}
    serial = body.pop("serialNumber")
    del body["version"]
    expected_body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {
                "components": [
                    {
                        "type": "platform",
                        "bom-ref": _INTERPRETER,
                        "name": "cpython",
                        "version": "3.15.0",
                        "purl": "pkg:generic/cpython@3.15.0",
                        "properties": [{"name": "python:implementation", "value": "CPython"}],
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/example@1.0",
                "name": "Example",
                "version": "1.0",
                "purl": "pkg:pypi/example@1.0",
                "externalReferences": [
                    {"type": "distribution", "url": "https://pypi.org/project/Example/1.0/"},
                    {
                        "type": "attestation",
                        "url": "https://pypi.org/integrity/Example/1.0/example-1.0-py3-none-any.whl/provenance",
                    },
                ],
                "properties": [],
            },
            "properties": [
                {
                    "name": "example:sbom:scope",
                    "value": "Components are the direct runtime dependencies declared in the wheel's core metadata,"
                    " which carry no version because the installer resolves them.",
                },
                {"name": "example:sbom:file", "value": "example.cdx.json"},
            ],
        },
        "components": [],
        "dependencies": [{"ref": "pkg:pypi/example@1.0", "dependsOn": []}],
        "compositions": [{"aggregate": "incomplete", "dependencies": ["pkg:pypi/example@1.0"]}],
        "formulation": [
            {
                "bom-ref": "formula:wheel-build",
                "workflows": [
                    {
                        "bom-ref": "workflow:wheel-build",
                        "uid": "wheel-build",
                        "name": "build the wheel and this SBOM",
                        "taskTypes": ["build"],
                        "resourceReferences": [{"ref": _INTERPRETER}],
                        "outputs": [{"type": "artifact", "resource": {"ref": "pkg:pypi/example@1.0"}}],
                    }
                ],
            }
        ],
    }
    assert body == expected_body
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://pypi.org/project/example/sboms")
    assert serial == f"urn:uuid:{uuid.uuid5(namespace, json.dumps(expected_body, sort_keys=True))}"


def test_header(describe: Describe) -> None:
    document = describe()
    header = {key: document[key] for key in ("$schema", "bomFormat", "specVersion", "version")}
    assert header == {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
    }


def test_serial_is_stable(describe: Describe) -> None:
    assert describe()["serialNumber"] == describe()["serialNumber"]


def test_serial_follows_content(describe: Describe) -> None:
    assert describe()["serialNumber"] != describe("Summary: other\n")["serialNumber"]


@pytest.mark.parametrize(
    ("dirty", "trail"),
    [
        pytest.param(False, ("c0ffee", "exact source revision", []), id="clean"),
        pytest.param(
            True,
            ("main", "source revision, with uncommitted changes", [{"name": "example:vcs-dirty", "value": "true"}]),
            id="dirty",
        ),
    ],
)
def test_root_component(
    describe: Describe,
    settings: Settings,
    facts: BuildFacts,
    dirty: bool,
    trail: tuple[str, str, list[dict[str, str]]],
) -> None:
    # a dirty checkout's files may differ from its commit's, so its links fall back to the default branch
    tree, comment, dirty_properties = trail
    supplier: OrganizationalEntity = {"name": "Example Org", "url": ["https://example.org"]}
    document = describe(
        "License-File: LICENSE\nProject-URL: Source, https://github.com/example/example/\n",
        settings=dataclasses.replace(settings, supplier=supplier),
        facts=dataclasses.replace(facts, revision=Revision(commit="c0ffee", dirty=dirty)),
        copyright_line="Copyright (c) 2026 Example",
    )
    repository = "https://github.com/example/example"
    assert document["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "pkg:pypi/example@1.0",
        "name": "Example",
        "version": "1.0",
        "purl": "pkg:pypi/example@1.0",
        "supplier": supplier,
        "copyright": "Copyright (c) 2026 Example",
        "externalReferences": [
            {"type": "vcs", "url": f"{repository}/", "comment": "Project-URL: Source"},
            {"type": "distribution", "url": "https://pypi.org/project/Example/1.0/"},
            {
                "type": "attestation",
                "url": "https://pypi.org/integrity/Example/1.0/example-1.0-py3-none-any.whl/provenance",
            },
            {"type": "security-contact", "url": f"{repository}/security/policy"},
            {"type": "advisories", "url": f"{repository}/security/advisories"},
            {"type": "license", "url": f"{repository}/blob/{tree}/LICENSE"},
            {"type": "vcs", "url": f"{repository}/tree/c0ffee", "comment": comment},
        ],
        "properties": [{"name": "example:vcs-commit", "value": "c0ffee"}, *dirty_properties],
    }


def test_supplier_makes_and_supplies_the_document(describe: Describe, settings: Settings) -> None:
    supplier: OrganizationalEntity = {"name": "Example Org", "url": []}
    metadata = describe(settings=dataclasses.replace(settings, supplier=supplier))["metadata"]
    assert metadata.get("manufacturer") == supplier
    assert metadata.get("supplier") == supplier


def test_metadata_repeats_root_authors_and_licenses(describe: Describe) -> None:
    metadata = describe("Author: Author\nLicense-Expression: MIT\n")["metadata"]
    assert metadata.get("authors") == [{"name": "Author"}]
    assert metadata.get("licenses") == [{"expression": "MIT", "acknowledgement": "declared"}]


def test_root_licenses_from_classifiers(describe: Describe) -> None:
    document = describe("Classifier: License :: OSI Approved :: MIT License\n")
    assert document["metadata"]["component"].get("licenses") == [
        {"license": {"name": "MIT License", "acknowledgement": "declared"}},
        {"license": {"id": "MIT", "acknowledgement": "concluded"}},
    ]


def test_repository_setting_wins_over_project_urls(describe: Describe, settings: Settings) -> None:
    document = describe(
        "Project-URL: Source, https://github.com/example/example\n",
        settings=dataclasses.replace(settings, repository="https://git.example.org/example"),
    )
    assert {"name": "example:sbom:repository", "value": "https://git.example.org/example"} in document["metadata"][
        "properties"
    ]


def test_no_security_links_outside_github(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, repository="https://git.example.org/example"))
    types = {reference["type"] for reference in document["metadata"]["component"]["externalReferences"]}
    assert types.isdisjoint({"security-contact", "advisories"})


def test_no_license_link_without_repository(describe: Describe) -> None:
    document = describe("License-File: LICENSE\n")
    types = {reference["type"] for reference in document["metadata"]["component"]["externalReferences"]}
    assert "license" not in types


def test_revision_without_repository_records_commit_only(describe: Describe, facts: BuildFacts) -> None:
    document = describe(facts=dataclasses.replace(facts, revision=Revision(commit="c0ffee", dirty=False)))
    root = document["metadata"]["component"]
    assert root["properties"] == [{"name": "example:vcs-commit", "value": "c0ffee"}]
    assert [reference["type"] for reference in root["externalReferences"]] == ["distribution", "attestation"]


@pytest.mark.parametrize(
    ("revision", "tree"),
    [
        pytest.param(None, "main", id="unknown"),
        pytest.param(Revision(commit="c0ffee", dirty=False), "c0ffee", id="clean"),
        pytest.param(Revision(commit="c0ffee", dirty=True), "main", id="dirty"),
    ],
)
def test_build_script_is_a_linked_tool(
    describe: Describe, settings: Settings, facts: BuildFacts, revision: Revision | None, tree: str
) -> None:
    document = describe(
        settings=dataclasses.replace(settings, repository="https://github.com/example/example"),
        facts=dataclasses.replace(facts, revision=revision),
        build_scripts=[BuildScript(path=PurePosixPath("hatch_build.py"), sha256="ef" * 32)],
    )
    assert document["metadata"]["tools"]["components"][0] == {
        "type": "application",
        "bom-ref": "tool:hatch_build.py",
        "name": "hatch_build.py",
        "version": "1.0",
        "hashes": [{"alg": "SHA-256", "content": "ef" * 32}],
        "externalReferences": [
            {"type": "vcs", "url": f"https://github.com/example/example/blob/{tree}/hatch_build.py"}
        ],
    }


@pytest.mark.parametrize(
    ("from_environment", "inputs"),
    [
        pytest.param(False, None, id="unset"),
        pytest.param(
            True, [{"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": "1700000000"}]}], id="from-environment"
        ),
    ],
)
def test_formulation_names_source_date_epoch_only_when_set(
    describe: Describe, facts: BuildFacts, from_environment: bool, inputs: list[dict[str, list[dict[str, str]]]] | None
) -> None:
    document = describe(facts=dataclasses.replace(facts, epoch_from_environment=from_environment))
    assert document.get("formulation", [])[0]["workflows"][0].get("inputs") == inputs


def test_contributions_join_before_references_and_serial(describe: Describe) -> None:
    library: Component = {"type": "library", "bom-ref": "pkg:generic/zlib@1.3", "name": "zlib", "version": "1.3"}
    tool: Component = {"type": "application", "bom-ref": "tool:pkg:generic/cmake@4", "name": "cmake", "version": "4"}

    class Native(ContentProvider):
        def __init__(self, components: list[Component]) -> None:
            self._components = components

        def contributions(self, context: ProviderContext) -> Contributions:
            return Contributions(
                components=self._components,
                dependencies=[{"ref": component["bom-ref"], "dependsOn": []} for component in self._components],
                root_properties=[{"name": "native:prefix", "value": context.identity.property_prefix}],
                tools=[tool],
            )

    native = describe(content=Native([library]))
    assert (
        native["components"],
        native["dependencies"],
        native["metadata"]["component"]["properties"],
        native["metadata"]["tools"]["components"][-1],
        native.get("formulation", [])[0]["workflows"][0]["resourceReferences"],
    ) == (
        [library],
        [
            {"ref": "pkg:pypi/example@1.0", "dependsOn": ["pkg:generic/zlib@1.3"]},
            {"ref": "pkg:generic/zlib@1.3", "dependsOn": []},
        ],
        [{"name": "native:prefix", "value": "example"}],
        tool,
        [{"ref": _INTERPRETER}, {"ref": "tool:pkg:generic/cmake@4"}],
    )
    assert native["serialNumber"] != describe()["serialNumber"]


_ORG: Final[OrganizationalEntity] = {"name": "Example Org", "url": []}
_PIP: Final[str] = "src/pip-1.0-py3-none-any.whl"


class _ProjectSupplies(ContentProvider):
    # the wheels the project builds itself, which its own supplier supplies
    def __init__(self, *own: str) -> None:
        self._own = frozenset(own)

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        if str(wheel) in self._own:
            return BundledWheelInfo(supplier=context.settings.supplier)
        return BundledWheelInfo()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(_ProjectSupplies(_PIP), _ORG, id="by-project"),
        pytest.param(_ProjectSupplies(), None, id="unnamed"),
    ],
)
def test_bundled_wheel_supplier_is_the_projects_choice(
    describe: Describe, settings: Settings, content: ContentProvider, expected: OrganizationalEntity | None
) -> None:
    wheel = BundledWheel(
        path=_PIP,
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\nProject-URL: Source, https://github.com/example/pip\n"),
        files=[],
        vendored=[],
    )
    document = describe(
        settings=dataclasses.replace(settings, supplier=_ORG),
        bundled=[wheel],
        content=content,
    )
    assert document["components"][0].get("supplier") == expected


def test_document_serial_derives_from_body() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://example.org/sboms")
    assert with_header(body, namespace) == {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def test_check_refs_refuses_repeated_refs() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "bom-ref": "app", "name": "tool"}]},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    with pytest.raises(SbomError, match="bom-ref values repeat: app"):
        check_refs(body)


def test_check_refs_refuses_unknown_dependency() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [{"ref": "app", "dependsOn": ["ghost"]}],
    }
    with pytest.raises(SbomError, match="dependencies name bom-refs no component has: ghost"):
        check_refs(body)


def test_contributed_properties_keep_their_own_prefix() -> None:
    properties: list[Property] = [{"name": "extra:key", "value": "1"}]
    assert contributed_properties(properties, "example") == properties


def test_contributed_properties_refuse_the_project_prefix() -> None:
    with pytest.raises(SbomError, match="example:vcs-commit use the example: prefix python-sbom writes"):
        contributed_properties([{"name": "example:vcs-commit", "value": "0"}], "example")


def _partial(**fields: str | list[dict[str, str]]) -> Component:
    # a component a provider got wrong, which the types alone would not let through
    return cast("Component", fields)


def test_check_refs_refuses_a_second_dependency_entry_for_a_ref() -> None:
    # as when a provider adds an entry for the root, whose entry python-sbom writes
    body = _body([], [{"ref": "app", "dependsOn": []}, {"ref": "app", "dependsOn": []}], [])
    with pytest.raises(SbomError, match="dependencies list more than one entry for: app"):
        check_refs(body)


def _body(components: list[Component], dependencies: list[Dependency], formulation: list[Formula]) -> Body:
    return {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": components,
        "dependencies": dependencies,
        "formulation": formulation,
    }


@pytest.mark.parametrize(
    "ref", [pytest.param("formula:build", id="formula"), pytest.param("workflow:build", id="workflow")]
)
def test_check_refs_refuses_a_component_taking_a_formulation_ref(facts: BuildFacts, ref: str) -> None:
    formula = formulation("build", "build the app", [], "app", facts)
    body = _body([{"type": "library", "bom-ref": ref, "name": "clash"}], [], [formula])
    with pytest.raises(SbomError, match=f"bom-ref values repeat: {ref}"):
        check_refs(body)


@pytest.mark.parametrize(
    ("contributions", "missing"),
    [
        pytest.param(Contributions(components=[_partial(type="library", name="zlib")]), "bom-ref", id="component"),
        pytest.param(
            Contributions(
                components=[
                    _partial(type="library", name="zlib", **{"bom-ref": "zlib", "components": [{"type": "file"}]})
                ]
            ),
            "bom-ref, name",
            id="nested",
        ),
        pytest.param(Contributions(tools=[_partial(name="cmake", **{"bom-ref": "tool:cmake"})]), "type", id="tool"),
    ],
)
def test_contributions_need_the_fields_the_build_reads(contributions: Contributions, missing: str) -> None:
    with pytest.raises(SbomError, match=f"content provider ContentProvider added a component without {missing}: "):
        checked_contributions(contributions, ContentProvider())


def test_complete_contributions_pass() -> None:
    contributions = Contributions(components=[{"type": "library", "bom-ref": "zlib", "name": "zlib"}])
    assert checked_contributions(contributions, ContentProvider()) is contributions
