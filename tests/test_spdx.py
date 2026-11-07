from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

import pytest

from hatch_pep770.spdx import to_spdx
from hatch_pep770.version import __version__

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from hatch_pep770.cyclonedx import Document
    from tests.conftest import BundleWheel

_BUNDLED: Final[str] = "src/example/wheels/*.whl"


@pytest.fixture
def bundled_config(bundle_wheel: BundleWheel, config: dict[str, Any]) -> dict[str, Any]:
    bundle_wheel(
        {"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"}, "Project-URL: Source, https://github.com/example/pip\n"
    )
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {
        "bundled-wheels": [_BUNDLED],
        "supplier": {"name": "Example Org"},
    }
    return config


def test_spdx_bundled_wheel(build_sbom: Callable[[dict[str, Any]], str], bundled_config: dict[str, Any]) -> None:
    cyclonedx: Final[Document] = json.loads(build_sbom(bundled_config))
    assert to_spdx(cyclonedx)["packages"][1] == {
        "SPDXID": "SPDXRef-pkg-pypi-pip-1.0",
        "name": "pip",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "primaryPackagePurpose": "LIBRARY",
        "versionInfo": "1.0",
        "supplier": "Organization: Example Org",
        "checksums": [{"algorithm": "SHA256", "checksumValue": cyclonedx["components"][0]["hashes"][0]["content"]}],
        "comment": "example:bundled-wheel: src/example/wheels/pip-1.0-py3-none-any.whl",
        "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/pip@1.0"}
        ],
    }


def test_spdx_root_package(sbom_document: Document) -> None:
    assert to_spdx(sbom_document)["packages"][0] == {
        "SPDXID": "SPDXRef-pkg-pypi-example-1.0",
        "name": "example",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "MIT",
        "primaryPackagePurpose": "APPLICATION",
        "versionInfo": "1.0",
        "copyrightText": "Copyright (c) 2026 Example",
        "summary": "an example",
        "comment": "example:requires-python: >=3.9",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/example@1.0",
            }
        ],
    }


def test_spdx_relationships(build_sbom: Callable[[dict[str, Any]], str], bundled_config: dict[str, Any]) -> None:
    assert [
        relationship
        for relationship in to_spdx(_load(build_sbom(bundled_config)))["relationships"]
        if not relationship["spdxElementId"].startswith("SPDXRef-tool-")
    ] == [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-pkg-pypi-example-1.0",
        },
        {
            "spdxElementId": "SPDXRef-pkg-pypi-pip-1.0",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-pkg-pypi-pip-1.0-vendored-pkg-pypi-urllib3-1.26.4",
        },
        {
            "spdxElementId": "SPDXRef-pkg-pypi-example-1.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-pkg-pypi-pip-1.0",
        },
        {
            "spdxElementId": "SPDXRef-pkg-pypi-example-1.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-requires-dist-packaging-24",
        },
        {
            "spdxElementId": "SPDXRef-pkg-pypi-example-1.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-requires-dist-tomli-2-python-version-3.11",
        },
        {
            "spdxElementId": "SPDXRef-pkg-pypi-pip-1.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-pkg-pypi-pip-1.0-vendored-pkg-pypi-urllib3-1.26.4",
        },
    ]


def test_spdx_build_tools(sbom_document: Document) -> None:
    assert {
        relationship["relatedSpdxElement"]
        for relationship in to_spdx(sbom_document)["relationships"]
        if relationship["relationshipType"] == "BUILD_TOOL_OF"
    } == {"SPDXRef-pkg-pypi-example-1.0"}


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        pytest.param("License-Expression: MIT\n", ("MIT", "NOASSERTION", None), id="expression"),
        pytest.param(
            "Classifier: License :: OSI Approved :: MIT License\nLicense: MIT\n",
            ("NOASSERTION", "MIT", "Declared in package metadata as: MIT License; MIT"),
            id="names",
        ),
        pytest.param(
            "License: LGPLv3\n",
            ("NOASSERTION", "NOASSERTION", "Declared in package metadata as: LGPLv3"),
            id="unresolved-name",
        ),
        pytest.param("", ("NOASSERTION", "NOASSERTION", None), id="undeclared"),
    ],
)
def test_spdx_declared_license(
    build_sbom: Callable[[dict[str, Any]], str],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
    metadata: str,
    expected: tuple[str, str, str | None],
) -> None:
    bundle_wheel({}, metadata)
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    package: Final[dict[str, Any]] = dict(to_spdx(_load(build_sbom(config)))["packages"][1])
    assert (package["licenseDeclared"], package["licenseConcluded"], package.get("licenseComments")) == expected


@pytest.mark.parametrize(
    ("urls", "hooks", "expected"),
    [
        pytest.param(
            {"Source": "https://github.com/example/example"},
            {"pep770": {"supplier": {"name": "Example Org"}}},
            ("https://github.com/example/example/sboms/example-1.0-", ["Organization: Example Org"]),
            id="repository-and-supplier",
        ),
        pytest.param({}, {"pep770": {}}, ("https://spdx.org/spdxdocs/sboms/example-1.0-", []), id="neither"),
        pytest.param(
            {},
            {"custom": {}},
            ("https://spdx.org/spdxdocs/sboms/example-1.0-", ["Tool: hatch_build.py-1.0"]),
            id="custom-build-script",
        ),
    ],
)
def test_spdx_creation_info(
    root: Path,
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    urls: dict[str, str],
    hooks: dict[str, Any],
    expected: tuple[str, list[str]],
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    (root / "hatch_build.py").write_text(
        "from hatch_pep770 import plugin\n\n\ndef get_build_hook():\n    return plugin.Pep770BuildHook\n",
        encoding="utf-8",
    )
    config["project"]["urls"] = urls
    config["tool"]["hatch"]["build"]["hooks"] = hooks
    cyclonedx: Final[Document] = json.loads(build_sbom(config))
    document: Final[dict[str, Any]] = dict(to_spdx(cyclonedx))
    namespace, creators = expected
    assert (
        document["documentNamespace"],
        document["creationInfo"],
        document["comment"],
    ) == (
        f"{namespace}{cyclonedx['serialNumber'].removeprefix('urn:uuid:')}",
        {"created": "2023-11-14T22:13:20Z", "creators": [*creators, f"Tool: hatch-pep770-{__version__}"]},
        (
            f"Rendered from the CycloneDX SBOM {cyclonedx['serialNumber']} (example.cdx.json), which also carries"
            " per-file hashes and the build formulation."
        ),
    )


def _load(content: str) -> Document:
    return json.loads(content)
