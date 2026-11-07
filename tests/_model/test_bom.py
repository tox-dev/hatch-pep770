from __future__ import annotations

import dataclasses
import json
import uuid
from email import message_from_string
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import BundledWheelInfo, ContentProvider, Contributions, ProviderContext
from python_sbom._model._inputs import BuildScript, BundledWheel, Revision, SourceTree

if TYPE_CHECKING:
    from conftest import Describe

    from python_sbom import Component
    from python_sbom._model._inputs import BuildFacts, Settings
    from python_sbom._model._types import OrganizationalEntity

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
        pytest.param(False, ("exact source revision", []), id="clean"),
        pytest.param(
            True,
            ("source revision, with uncommitted changes", [{"name": "example:vcs-dirty", "value": "true"}]),
            id="dirty",
        ),
    ],
)
def test_root_component(
    describe: Describe, settings: Settings, facts: BuildFacts, dirty: bool, trail: tuple[str, list[dict[str, str]]]
) -> None:
    comment, dirty_properties = trail
    supplier: OrganizationalEntity = {"name": "Example Org", "url": ["https://example.org"]}
    document = describe(
        "License-File: LICENSE\nProject-URL: Source, https://github.com/example/example/\n",
        settings=dataclasses.replace(settings, supplier=supplier),
        facts=dataclasses.replace(facts, revision=Revision(commit="c0ffee", dirty=dirty)),
        source=SourceTree(copyright="Copyright (c) 2026 Example", bundled=[], build_scripts=[]),
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
            {"type": "license", "url": f"{repository}/blob/main/LICENSE"},
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


def test_declared_dependency(describe: Describe) -> None:
    requirement = 'tomli>=2; python_version < "3.11"'
    document = describe(f"Requires-Dist: {requirement}\n")
    assert document["components"] == [
        {
            "type": "library",
            "bom-ref": f"requires-dist:{requirement}",
            "name": "tomli",
            "purl": "pkg:pypi/tomli",
            "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/tomli/"}],
            "properties": [
                {"name": "example:requires-dist", "value": requirement},
                {"name": "example:environment-marker", "value": 'python_version < "3.11"'},
            ],
        }
    ]


def test_repeated_requirement_is_one_component(describe: Describe) -> None:
    document = describe("Requires-Dist: packaging>=24\nRequires-Dist: packaging>=24\n")
    assert [component["bom-ref"] for component in document["components"]] == ["requires-dist:packaging>=24"]


def test_scope_names_bundled_directories(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, bundled_wheels=("src/b/*.whl", "src/a/x/*.whl")))
    assert document["metadata"]["properties"][0]["value"] == (
        "Components are the wheels bundled as data files under src/a/x and src/b and the direct runtime dependencies"
        " declared in the wheel's core metadata, which carry no version because the installer resolves them."
    )


def test_bundled_wheel_and_its_vendored_packages(describe: Describe) -> None:
    wheel = BundledWheel(
        path="src/pip-1.0-py3-none-any.whl",
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=message_from_string("Name: pip\nVersion: 1.0\n"),
        files=[],
        vendored=[("pip/_vendor/vendor.txt", message_from_string("Name: urllib3\nVersion: 1.26.4\n"))],
    )

    class Seeded(ContentProvider):
        def __init__(self, name: str) -> None:
            self._name = name

        def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
            return BundledWheelInfo(
                properties=[{"name": f"{context.identity.property_prefix}:{self._name}", "value": str(wheel)}]
            )

    document = describe(source=SourceTree(copyright=None, bundled=[wheel], build_scripts=[]), content=Seeded("seeded"))
    assert document["components"][0]["properties"][1] == {
        "name": "example:seeded",
        "value": "src/pip-1.0-py3-none-any.whl",
    }
    bundled_ref = "bundled:src/pip-1.0-py3-none-any.whl"
    assert document["dependencies"][:2] == [
        {"ref": "pkg:pypi/example@1.0", "dependsOn": [bundled_ref]},
        {"ref": bundled_ref, "dependsOn": [f"{bundled_ref}#vendored/pkg:pypi/urllib3@1.26.4"]},
    ]


def test_build_script_is_a_linked_tool(describe: Describe, settings: Settings) -> None:
    source = SourceTree(
        copyright=None,
        bundled=[],
        build_scripts=[BuildScript(path=PurePosixPath("hatch_build.py"), sha256="ef" * 32)],
    )
    document = describe(
        settings=dataclasses.replace(settings, repository="https://github.com/example/example"), source=source
    )
    assert document["metadata"]["tools"]["components"][0] == {
        "type": "application",
        "bom-ref": "tool:hatch_build.py",
        "name": "hatch_build.py",
        "version": "1.0",
        "hashes": [{"alg": "SHA-256", "content": "ef" * 32}],
        "externalReferences": [{"type": "vcs", "url": "https://github.com/example/example/blob/main/hatch_build.py"}],
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


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [pytest.param(True, _ORG, id="by-project"), pytest.param(False, None, id="unnamed")],
)
def test_bundled_wheel_supplier_is_the_projects_choice(
    describe: Describe, settings: Settings, supplied: bool, expected: OrganizationalEntity | None
) -> None:
    wheel = BundledWheel(
        path="src/pip-1.0-py3-none-any.whl",
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=message_from_string("Name: pip\nVersion: 1.0\nProject-URL: Source, https://github.com/example/pip\n"),
        files=[],
        vendored=[],
    )

    class Supplied(ContentProvider):
        def __init__(self, supplied: bool) -> None:
            self._supplied = supplied

        def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:  # ruff: ignore[unused-method-argument] # the base class's signature
            return BundledWheelInfo(supplier=context.settings.supplier if self._supplied else None)

    document = describe(
        settings=dataclasses.replace(settings, supplier=_ORG),
        source=SourceTree(copyright=None, bundled=[wheel], build_scripts=[]),
        content=Supplied(supplied),
    )
    assert document["components"][0].get("supplier") == expected
