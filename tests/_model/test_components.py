from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import BundledWheelInfo
from python_sbom._model._components import (
    bundled_wheel_component,
    component_from_metadata,
    script_tool,
    vendored_dependencies,
)
from python_sbom._model._inputs import BundledWheel, RecordRow
from python_sbom._model._metadata import parse_metadata
from python_sbom._model._names import purl

if TYPE_CHECKING:
    from python_sbom import Component, Property
    from python_sbom._model._types import License, OrganizationalEntity

_WHEEL: Final[str] = "src/example/wheels/pip-1.0-py3-none-any.whl"


def test_component_from_metadata() -> None:
    metadata = parse_metadata(
        "Name: Example\nVersion: 1.0\nSummary: an example\nMaintainer-email: Maintainer <maintainer@example.com>\n"
        "License-Expression: MIT\nRequires-Python: >=3.11\nRequires-Dist: packaging>=24\nProvides-Extra: cli\n"
        "Classifier: Programming Language :: Python :: 3\nKeywords: sample,demo\n"
        "Project-URL: Source, https://github.com/example/example\n"
    )
    assert component_from_metadata(metadata) == {
        "type": "library",
        "bom-ref": "pkg:pypi/example@1.0",
        "name": "Example",
        "version": "1.0",
        "purl": "pkg:pypi/example@1.0",
        "description": "an example",
        "authors": [{"name": "Maintainer", "email": "maintainer@example.com"}],
        "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/example/example", "comment": "Project-URL: Source"}
        ],
        "properties": [
            {"name": "python:requires-python", "value": ">=3.11"},
            {"name": "python:requires-dist", "value": "packaging>=24"},
            {"name": "python:provides-extra", "value": "cli"},
            {"name": "python:classifier", "value": "Programming Language :: Python :: 3"},
            {"name": "python:keywords", "value": "sample,demo"},
        ],
    }


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        pytest.param("Author: Author\nMaintainer: Maintainer\n", [{"name": "Maintainer"}], id="maintainer-wins"),
        pytest.param(
            "Author-email: Author <author@example.com>, other@example.com\n",
            [{"name": "Author", "email": "author@example.com"}, {"email": "other@example.com"}],
            id="authors-without-maintainer",
        ),
        pytest.param(
            "Author-email: Jane Doe <jane at example.com>\n", [{"name": "Jane Doe jane at example.com"}], id="bad-email"
        ),
    ],
)
def test_component_authors(fields: str, expected: list[dict[str, str]]) -> None:
    assert component_from_metadata(parse_metadata(f"Name: a\nVersion: 1\n{fields}"))["authors"] == expected


def test_component_without_authors_has_no_key() -> None:
    assert "authors" not in component_from_metadata(parse_metadata("Name: a\nVersion: 1\n"))


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        pytest.param(
            "Classifier: License :: OSI Approved :: MIT License\n",
            [
                {"license": {"name": "MIT License", "acknowledgement": "declared"}},
                {"license": {"id": "MIT", "acknowledgement": "concluded"}},
            ],
            id="classifier",
        ),
        pytest.param(
            "License: apache-2.0\n",
            [
                {"license": {"name": "apache-2.0", "acknowledgement": "declared"}},
                {"license": {"id": "Apache-2.0", "acknowledgement": "concluded"}},
            ],
            id="license-field",
        ),
        pytest.param(
            "Classifier: License :: OSI Approved :: MIT License\nLicense: MIT\n",
            [
                {"license": {"name": "MIT License", "acknowledgement": "declared"}},
                {"license": {"name": "MIT", "acknowledgement": "declared"}},
                {"license": {"id": "MIT", "acknowledgement": "concluded"}},
            ],
            id="same-id-once",
        ),
        pytest.param(
            "Classifier: License :: OSI Approved :: BSD License\nLicense: MIT\n",
            [
                {"license": {"name": "BSD License", "acknowledgement": "declared"}},
                {"license": {"name": "MIT", "acknowledgement": "declared"}},
            ],
            id="one-unresolved-name-concludes-nothing",
        ),
        pytest.param(
            "License: LicenseRef-Proprietary\n",
            [{"license": {"name": "LicenseRef-Proprietary", "acknowledgement": "declared"}}],
            id="license-ref",
        ),
        pytest.param(
            "License: MIT OR Apache-2.0\n",
            [{"license": {"name": "MIT OR Apache-2.0", "acknowledgement": "declared"}}],
            id="expression-in-license-field",
        ),
        pytest.param(
            "License: not a license\n",
            [{"license": {"name": "not a license", "acknowledgement": "declared"}}],
            id="invalid-expression",
        ),
    ],
)
def test_component_licenses(fields: str, expected: list[License]) -> None:
    assert component_from_metadata(parse_metadata(f"Name: a\nVersion: 1\n{fields}"))["licenses"] == expected


def test_component_ignores_license_text() -> None:
    metadata = parse_metadata("Name: a\nVersion: 1\nLicense: Copyright\n        the full text\n")
    assert "licenses" not in component_from_metadata(metadata)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        pytest.param("Home-page: UNKNOWN\n", [], id="unknown-home-page"),
        pytest.param(
            "Home-page: https://example.com\n", [{"type": "website", "url": "https://example.com"}], id="home-page"
        ),
        pytest.param("Project-URL: no comma\n", [], id="url-without-label"),
        pytest.param(
            "Project-URL: Bug Tracker, https://example.com/issues\n",
            [{"type": "issue-tracker", "url": "https://example.com/issues", "comment": "Project-URL: Bug Tracker"}],
            id="normalized-label",
        ),
        pytest.param(
            "Project-URL: Source Code, https://example.com/x\n",
            [{"type": "vcs", "url": "https://example.com/x", "comment": "Project-URL: Source Code"}],
            id="pep-753-source-code",
        ),
        pytest.param(
            "Project-URL: Bugs, https://example.com/x\n",
            [{"type": "issue-tracker", "url": "https://example.com/x", "comment": "Project-URL: Bugs"}],
            id="pep-753-bugs",
        ),
        pytest.param(
            "Project-URL: Issue, https://example.com/x\n",
            [{"type": "issue-tracker", "url": "https://example.com/x", "comment": "Project-URL: Issue"}],
            id="pep-753-issue",
        ),
        pytest.param(
            "Project-URL: Release Notes, https://example.com/x\n",
            [{"type": "release-notes", "url": "https://example.com/x", "comment": "Project-URL: Release Notes"}],
            id="pep-753-release-notes",
        ),
        pytest.param(
            "Project-URL: What's New, https://example.com/x\n",
            [{"type": "release-notes", "url": "https://example.com/x", "comment": "Project-URL: What's New"}],
            id="pep-753-whats-new",
        ),
        pytest.param(
            "Project-URL: History, https://example.com/x\n",
            [{"type": "release-notes", "url": "https://example.com/x", "comment": "Project-URL: History"}],
            id="pep-753-history",
        ),
        pytest.param(
            "Project-URL: Funding, https://example.com/fund\n",
            [{"type": "other", "url": "https://example.com/fund", "comment": "Project-URL: Funding"}],
            id="unknown-label",
        ),
    ],
)
def test_component_references(fields: str, expected: list[dict[str, str]]) -> None:
    component = component_from_metadata(parse_metadata(f"Name: a\nVersion: 1\n{fields}"))
    assert component["externalReferences"] == expected


def test_bundled_wheel_component() -> None:
    wheel = BundledWheel(
        path=_WHEEL,
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\n"),
        files=[RecordRow(path="pip/__init__.py", algorithm="SHA-256", digest="cd" * 32, size="0")],
        vendored=[],
    )
    supplier: OrganizationalEntity = {"name": "PyPA", "url": ["https://www.pypa.io"]}
    properties: list[Property] = [{"name": "example:seeded-for-python", "value": "3.15"}]
    assert bundled_wheel_component(wheel, "example", BundledWheelInfo(properties=properties, supplier=supplier)) == {
        "type": "library",
        "bom-ref": f"bundled:{_WHEEL}",
        "name": "pip",
        "version": "1.0",
        "purl": "pkg:pypi/pip@1.0",
        "supplier": supplier,
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/pip/1.0/"}],
        "properties": [
            {"name": "example:bundled-wheel", "value": _WHEEL},
            {"name": "example:seeded-for-python", "value": "3.15"},
        ],
        "evidence": {
            "identity": [
                {
                    "field": "purl",
                    "confidence": 1,
                    "methods": [
                        {"technique": "manifest-analysis", "confidence": 1, "value": "pip-1.0.dist-info/METADATA"}
                    ],
                },
                {
                    "field": "hash",
                    "confidence": 1,
                    "methods": [{"technique": "hash-comparison", "confidence": 1, "value": "ab" * 32}],
                },
            ]
        },
        "components": [
            {
                "type": "file",
                "bom-ref": f"bundled:{_WHEEL}#pip/__init__.py",
                "name": "pip/__init__.py",
                "hashes": [{"alg": "SHA-256", "content": "cd" * 32}],
                "properties": [{"name": "size", "value": "0"}],
            }
        ],
    }


def test_bundled_wheel_vendored_metadata_wins_over_manifest() -> None:
    manifest = "pip/_vendor/vendor.txt"
    dist_info = "pip/_vendor/urllib3-1.26.4.dist-info/METADATA"
    wheel = BundledWheel(
        path=_WHEEL,
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\n"),
        files=[],
        vendored=[
            (manifest, parse_metadata("Name: urllib3\nVersion: 1.26.4\n")),
            (dist_info, parse_metadata("Name: urllib3\nVersion: 1.26.4\nLicense-Expression: MIT\n")),
        ],
    )
    component = bundled_wheel_component(wheel, "example", BundledWheelInfo())
    assert component["components"] == [
        {
            "type": "library",
            "bom-ref": f"bundled:{_WHEEL}#vendored/pkg:pypi/urllib3@1.26.4",
            "name": "urllib3",
            "version": "1.26.4",
            "purl": "pkg:pypi/urllib3@1.26.4",
            "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
            "externalReferences": [],
            "properties": [{"name": "example:vendored-manifest", "value": dist_info}],
            "evidence": {
                "identity": [
                    {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": dist_info}],
                    }
                ]
            },
        }
    ]


def test_bundled_wheel_component_ref_tells_copies_apart() -> None:
    def component(path: str) -> Component:
        wheel = BundledWheel(
            path=path,
            sha256="ab" * 32,
            metadata_name="pip-1.0.dist-info/METADATA",
            metadata=parse_metadata("Name: pip\nVersion: 1.0\n"),
            files=[],
            vendored=[],
        )
        return bundled_wheel_component(wheel, "example", BundledWheelInfo())

    refs = {component(f"src/{directory}/pip-1.0-py3-none-any.whl")["bom-ref"] for directory in ("a", "b")}
    assert refs == {"bundled:src/a/pip-1.0-py3-none-any.whl", "bundled:src/b/pip-1.0-py3-none-any.whl"}


def test_bundled_wheel_supplier_never_comes_from_the_wheel() -> None:
    wheel = BundledWheel(
        path=_WHEEL,
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\nProject-URL: Source, https://github.com/example/pip\n"),
        files=[],
        vendored=[],
    )
    component = bundled_wheel_component(wheel, "example", BundledWheelInfo())
    assert "supplier" not in component


def test_script_tool_with_link() -> None:
    tool = script_tool(PurePosixPath("build/hook.py"), "ef" * 32, "1.0", "https://example.com/hook.py")
    assert tool == {
        "type": "application",
        "bom-ref": "tool:build/hook.py",
        "name": "hook.py",
        "version": "1.0",
        "hashes": [{"alg": "SHA-256", "content": "ef" * 32}],
        "externalReferences": [{"type": "vcs", "url": "https://example.com/hook.py"}],
    }


def test_script_tool_without_link() -> None:
    assert "externalReferences" not in script_tool(PurePosixPath("hook.py"), "ef" * 32, "1.0", None)


def test_vendored_spellings_of_one_package_merge() -> None:
    wheel = BundledWheel(
        path=_WHEEL,
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\n"),
        files=[],
        vendored=[
            ("pip/_vendor/vendor.txt", parse_metadata("Name: jaraco.text\nVersion: 4.0\n")),
            (
                "pip/_vendor/jaraco_text-4.0.dist-info/METADATA",
                parse_metadata("Name: jaraco_text\nVersion: 4.0\n"),
            ),
        ],
    )
    component = bundled_wheel_component(wheel, "example", BundledWheelInfo())
    assert [child["name"] for child in component.get("components", [])] == ["jaraco_text"]


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("jaraco.context", id="dots"),
        pytest.param("jaraco_context", id="underscore"),
        pytest.param("Jaraco-Context", id="case"),
        pytest.param("jaraco..context", id="run-of-separators"),
    ],
)
def test_spellings_of_one_project_share_a_purl(name: str) -> None:
    component = component_from_metadata(parse_metadata(f"Name: {name}\nVersion: 6.1.0\n"))
    assert (component["purl"], component["bom-ref"]) == (
        "pkg:pypi/jaraco-context@6.1.0",
        "pkg:pypi/jaraco-context@6.1.0",
    )


def test_purl_escapes_a_local_version() -> None:
    # the purl spec percent-encodes every version character outside its unreserved set, + among them
    assert purl("pkg", "1.0+local.1") == "pkg:pypi/pkg@1.0%2Blocal.1"


def test_vendored_dependencies_at_any_depth_in_document_order() -> None:
    def bundled(ref: str, *children: Component) -> Component:
        return {"type": "library", "bom-ref": ref, "name": ref, "components": list(children)}

    vendored: Component = {"type": "library", "bom-ref": "bundled:b.whl#vendored/pkg:pypi/six@1", "name": "six"}
    # a file whose path holds the marker is no vendored package
    file: Component = {"type": "file", "bom-ref": "bundled:a.whl#x#vendored/y", "name": "x#vendored/y"}
    components = [
        bundled("pkg:pypi/app@1", bundled("bundled:a.whl", file), bundled("bundled:b.whl", vendored)),
        bundled("bundled:c.whl", {**vendored, "bom-ref": "bundled:c.whl#vendored/pkg:pypi/six@1"}),
    ]
    assert vendored_dependencies(components) == [
        {"ref": "bundled:b.whl", "dependsOn": ["bundled:b.whl#vendored/pkg:pypi/six@1"]},
        {"ref": "bundled:c.whl", "dependsOn": ["bundled:c.whl#vendored/pkg:pypi/six@1"]},
    ]


@pytest.mark.parametrize(
    ("fields", "references", "kept"),
    [
        pytest.param(
            "Project-URL: Source, git@github.com:example/pkg.git\n",
            [],
            [{"name": "python:project-url", "value": "Source, git@github.com:example/pkg.git"}],
            id="scp-style-git",
        ),
        pytest.param(
            "Project-URL: Docs, https://example.org/my docs\n",
            [{"type": "documentation", "url": "https://example.org/my%20docs", "comment": "Project-URL: Docs"}],
            [{"name": "python:project-url", "value": "Docs, https://example.org/my docs"}],
            id="space",
        ),
        pytest.param(
            "Project-URL: Template, https://example.org/{name}/x\n",
            [{"type": "other", "url": "https://example.org/%7Bname%7D/x", "comment": "Project-URL: Template"}],
            [{"name": "python:project-url", "value": "Template, https://example.org/{name}/x"}],
            id="braces",
        ),
        pytest.param(
            "Home-page: https://example.org/a b\n",
            [{"type": "website", "url": "https://example.org/a%20b"}],
            [{"name": "python:home-page", "value": "https://example.org/a b"}],
            id="home-page-space",
        ),
        pytest.param(
            "Home-page: https://example.org:port/\n",
            [],
            [{"name": "python:home-page", "value": "https://example.org:port/"}],
            id="home-page-bad-port",
        ),
        pytest.param(
            "Home-page: https://example.org/\nProject-URL: Source, https://github.com/example/pkg\n",
            [
                {"type": "website", "url": "https://example.org/"},
                {"type": "vcs", "url": "https://github.com/example/pkg", "comment": "Project-URL: Source"},
            ],
            [],
            id="valid-kept-as-is",
        ),
    ],
)
def test_url_no_iri_reference_is_encoded_or_kept_as_property(
    fields: str, references: list[dict[str, str]], kept: list[dict[str, str]]
) -> None:
    # validation requires an IRI reference, so a URL copied as written would build an SBOM validate rejects
    component = component_from_metadata(parse_metadata(f"Name: a\nVersion: 1\n{fields}"))
    assert (component["externalReferences"], component["properties"]) == (references, kept)
