from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from conftest import BUNDLED, HOOK

from python_sbom import __version__, to_spdx

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import BuildSbom, BundleWheel

    from python_sbom import Document

_SUPPLIED: Final[str] = f'{HOOK}{BUNDLED}supplier = {{ name = "Example Org" }}\n'


@pytest.fixture
def bundled(bundle_wheel: BundleWheel) -> None:
    bundle_wheel(
        {"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"}, "Project-URL: Source, https://github.com/example/pip\n"
    )


@pytest.mark.usefixtures("bundled")
def test_spdx_bundled_wheel(build_sbom: BuildSbom) -> None:
    cyclonedx: Final[Document] = build_sbom(hook=_SUPPLIED)
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
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": cyclonedx["components"][0].get("hashes", [])[0]["content"]}
        ],
        "comment": "example:bundled-wheel: src/example/wheels/pip-1.0-py3-none-any.whl",
        "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/pip@1.0"}
        ],
    }


def test_spdx_root_package(build_sbom: BuildSbom) -> None:
    assert to_spdx(build_sbom())["packages"][0] == {
        "SPDXID": "SPDXRef-pkg-pypi-example-1.0",
        "name": "Example",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "MIT",
        "primaryPackagePurpose": "APPLICATION",
        "versionInfo": "1.0",
        "copyrightText": "Copyright (c) 2026 Example",
        "summary": "an example",
        "comment": "example:requires-python: >=3.11",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/example@1.0",
            }
        ],
    }


@pytest.mark.usefixtures("bundled")
def test_spdx_relationships(build_sbom: BuildSbom) -> None:
    assert [
        relationship
        for relationship in to_spdx(build_sbom(hook=_SUPPLIED))["relationships"]
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


def test_spdx_build_tools(build_sbom: BuildSbom) -> None:
    assert {
        relationship["relatedSpdxElement"]
        for relationship in to_spdx(build_sbom())["relationships"]
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
    build_sbom: BuildSbom, bundle_wheel: BundleWheel, metadata: str, expected: tuple[str, str, str | None]
) -> None:
    bundle_wheel({}, metadata)
    package = to_spdx(build_sbom(hook=f"{HOOK}{BUNDLED}"))["packages"][1]
    assert (package["licenseDeclared"], package["licenseConcluded"], package.get("licenseComments")) == expected


@pytest.mark.parametrize(
    ("hook", "expected"),
    [
        pytest.param(
            f'{HOOK}supplier = {{ name = "Example Org" }}\n',
            ("https://github.com/example/example/sboms/Example-1.0-", ["Organization: Example Org"]),
            id="repository-and-supplier",
        ),
        pytest.param(
            '[tool.hatch.build.hooks.custom]\npath = "build.py"\n',
            ("https://github.com/example/example/sboms/Example-1.0-", ["Tool: build.py-1.0"]),
            id="custom-build-script",
        ),
    ],
)
def test_spdx_creation_info(
    root: Path, build_sbom: BuildSbom, monkeypatch: pytest.MonkeyPatch, hook: str, expected: tuple[str, list[str]]
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    (root / "build.py").write_text(
        "from python_sbom import SbomBuildHook\n\n\ndef get_build_hook():\n    return SbomBuildHook\n",
        encoding="utf-8",
    )
    cyclonedx: Final[Document] = build_sbom(hook=hook)
    spdx = to_spdx(cyclonedx)
    namespace, creators = expected
    assert (spdx["documentNamespace"], spdx["creationInfo"], spdx["comment"]) == (
        f"{namespace}{cyclonedx['serialNumber'].removeprefix('urn:uuid:')}",
        {"created": "2023-11-14T22:13:20Z", "creators": [*creators, f"Tool: python-sbom-{__version__}"]},
        (
            f"Rendered from the CycloneDX SBOM {cyclonedx['serialNumber']} (example.cdx.json), which also carries"
            " per-file hashes and the build formulation."
        ),
    )


def test_spdx_namespace_without_repository(build_sbom: BuildSbom) -> None:
    cyclonedx: Final[Document] = build_sbom(project='[project]\nname = "Example"\nversion = "1.0"\n')
    assert to_spdx(cyclonedx)["documentNamespace"] == (
        f"https://spdx.org/spdxdocs/sboms/Example-1.0-{cyclonedx['serialNumber'].removeprefix('urn:uuid:')}"
    )
