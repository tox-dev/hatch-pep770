from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder

from hatch_pep770.validate import wheel_problems

if TYPE_CHECKING:
    from collections.abc import Callable

    from pytest_mock import MockerFixture

    from hatch_pep770.cyclonedx import Component, Document, Workflow
    from tests.conftest import BundleWheel, InstallTool

_BUNDLED: Final[str] = "src/example/wheels/*.whl"
_URLS: Final[dict[str, str]] = {"Source": "https://github.com/example/example"}


@pytest.mark.skipif(sys.version_info < (3, 10), reason="hatchling 1.28 needs Python 3.10")
def test_wheel_embeds_sbom(
    build_wheel: Callable[[dict[str, Any], str], Path], config: dict[str, Any]
) -> None:  # pragma: >=3.10 cover
    with zipfile.ZipFile(build_wheel(config, "dist")) as archive:
        names: Final[list[str]] = archive.namelist()
        record: Final[str] = archive.read("example-1.0.dist-info/RECORD").decode("utf-8")
    assert ("example-1.0.dist-info/sboms/example.cdx.json" in names, "sboms/example.cdx.json," in record) == (
        True,
        True,
    )


@pytest.mark.skipif(sys.version_info < (3, 10), reason="hatchling 1.28 needs Python 3.10")
def test_wheel_sbom_valid(
    build_wheel: Callable[[dict[str, Any], str], Path],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
) -> None:  # pragma: >=3.10 cover
    bundle_wheel({"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"}, "License-Expression: MIT\n")
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    assert wheel_problems(build_wheel(config, "dist"), frozenset({"MIT"})) == []


@pytest.mark.skipif(sys.version_info < (3, 10), reason="hatchling 1.28 needs Python 3.10")
def test_wheel_reproducible(
    build_wheel: Callable[[dict[str, Any], str], Path], config: dict[str, Any]
) -> None:  # pragma: >=3.10 cover
    assert build_wheel(config, "first").read_bytes() == build_wheel(config, "second").read_bytes()


@pytest.mark.skipif(sys.version_info >= (3, 10), reason="Python 3.10 and later get hatchling 1.28")
def test_wheel_old_hatchling(
    build_wheel: Callable[[dict[str, Any], str], Path], config: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:  # pragma: <3.10 cover
    with zipfile.ZipFile(build_wheel(config, "dist")) as archive:
        sboms: Final[list[str]] = [name for name in archive.namelist() if "/sboms/" in name]
    assert (sboms, "cannot embed SBOMs" in capsys.readouterr().err) == ([], True)


def test_sdist_target_skipped(root: Path, config: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    (artifact,) = SdistBuilder(str(root), config=config).build(directory=str(root / "dist"))
    assert (Path(artifact).name, capsys.readouterr().err) == ("example-1.0.tar.gz", "")


def test_root_component(sbom_document: Document) -> None:
    attestation: Final[str] = "https://pypi.org/integrity/example/1.0/example-1.0-py3-none-any.whl/provenance"
    assert sbom_document["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "pkg:pypi/example@1.0",
        "authors": [{"name": "Maintainer", "email": "maintainer@example.com"}],
        "name": "example",
        "version": "1.0",
        "description": "an example",
        "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
        "copyright": "Copyright (c) 2026 Example",
        "purl": "pkg:pypi/example@1.0",
        "externalReferences": [
            {"type": "release-notes", "url": "https://example.com/changelog", "comment": "Project-URL: Changelog"},
            {"type": "vcs", "url": "https://github.com/example/example", "comment": "Project-URL: Source"},
            {"type": "distribution", "url": "https://pypi.org/project/example/1.0/"},
            {"type": "attestation", "url": attestation},
            {"type": "security-contact", "url": "https://github.com/example/example/security/policy"},
            {"type": "advisories", "url": "https://github.com/example/example/security/advisories"},
            {"type": "license", "url": "https://github.com/example/example/blob/main/LICENSE"},
        ],
        "properties": [
            {"name": "example:requires-python", "value": ">=3.9"},
            {"name": "python:classifier", "value": "Programming Language :: Python :: 3"},
            {"name": "python:keyword", "value": "sample"},
        ],
    }


def test_root_component_minimal_metadata(
    root: Path, build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any]
) -> None:
    (root / "LICENSE").write_text("MIT terms\n", encoding="utf-8")
    config["project"] = {
        "name": "example",
        "version": "1.0",
        "license-files": ["LICENSE"],
        "authors": [{"name": "Author"}],
    }
    assert json.loads(build_sbom(config))["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "pkg:pypi/example@1.0",
        "authors": [{"name": "Author"}],
        "name": "example",
        "version": "1.0",
        "purl": "pkg:pypi/example@1.0",
        "externalReferences": [
            {"type": "distribution", "url": "https://pypi.org/project/example/1.0/"},
            {
                "type": "attestation",
                "url": "https://pypi.org/integrity/example/1.0/example-1.0-py2.py3-none-any.whl/provenance",
            },
        ],
        "properties": [],
    }


def test_document_metadata(sbom_document: Document) -> None:
    assert {key: value for key, value in sbom_document["metadata"].items() if key not in {"tools", "component"}} == {
        "timestamp": "2020-02-02T00:00:00+00:00",
        "lifecycles": [{"phase": "build"}],
        "authors": [{"name": "Maintainer", "email": "maintainer@example.com"}],
        "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
        "properties": [
            {
                "name": "example:sbom:scope",
                "value": "Components are the direct runtime dependencies declared in the wheel's core metadata. They"
                " carry no version because they are resolved at install time, not at build time.",
            }
        ],
    }


def test_supplier(build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any]) -> None:
    supplier: Final[dict[str, Any]] = {"name": "Example Org", "url": ["https://example.org"]}
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"supplier": supplier}
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    assert [
        document["metadata"]["manufacturer"],
        document["metadata"]["supplier"],
        document["metadata"]["component"]["supplier"],
    ] == [supplier] * 3


def test_declared_dependencies(sbom_document: Document) -> None:
    assert (sbom_document["components"], sbom_document["dependencies"][0]) == (
        [
            {
                "type": "library",
                "bom-ref": "requires-dist:packaging>=24",
                "name": "packaging",
                "purl": "pkg:pypi/packaging",
                "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/packaging/"}],
                "properties": [{"name": "example:requires-dist", "value": "packaging>=24"}],
            },
            {
                "type": "library",
                "bom-ref": "requires-dist:tomli>=2; python_version < '3.11'",
                "name": "tomli",
                "purl": "pkg:pypi/tomli",
                "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/tomli/"}],
                "properties": [
                    {"name": "example:requires-dist", "value": "tomli>=2; python_version < '3.11'"},
                    {"name": "example:environment-marker", "value": 'python_version < "3.11"'},
                ],
            },
        ],
        {
            "ref": "pkg:pypi/example@1.0",
            "dependsOn": ["requires-dist:packaging>=24", "requires-dist:tomli>=2; python_version < '3.11'"],
        },
    )


def test_composition_incomplete(sbom_document: Document) -> None:
    assert sbom_document["compositions"] == [{"aggregate": "incomplete", "dependencies": ["pkg:pypi/example@1.0"]}]


def test_build_workflow(sbom_document: Document) -> None:
    workflow: Final[Workflow] = sbom_document["formulation"][0]["workflows"][0]
    assert {**workflow, "resourceReferences": len(workflow["resourceReferences"])} == {
        "bom-ref": "workflow:wheel-build",
        "uid": "wheel-build",
        "name": "build the wheel and this SBOM",
        "taskTypes": ["build"],
        "resourceReferences": len(sbom_document["metadata"]["tools"]["components"]),
        "outputs": [{"type": "artifact", "resource": {"ref": "pkg:pypi/example@1.0"}}],
        "inputs": [{"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": "1580601600"}]}],
    }


def test_build_tools_name_interpreter_and_hook(sbom_document: Document) -> None:
    tools: Final[list[Component]] = sbom_document["metadata"]["tools"]["components"]
    assert (tools[0]["type"], any(tool["name"] == "hatch-pep770" for tool in tools)) == ("platform", True)


def test_bundled_wheel(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    wheel: Final[Path] = bundle_wheel({}, "License-Expression: MIT\n")
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    sha256: Final[str] = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert json.loads(build_sbom(config))["components"][0] == {
        "type": "library",
        "bom-ref": "pkg:pypi/pip@1.0",
        "name": "pip",
        "version": "1.0",
        "purl": "pkg:pypi/pip@1.0",
        "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
        "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/pip/1.0/"}],
        "properties": [{"name": "example:bundled-wheel", "value": "src/example/wheels/pip-1.0-py3-none-any.whl"}],
        "hashes": [{"alg": "SHA-256", "content": sha256}],
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
                    "methods": [{"technique": "hash-comparison", "confidence": 1, "value": sha256}],
                },
            ]
        },
        "components": [
            {
                "type": "file",
                "bom-ref": "pkg:pypi/pip@1.0#pip/example.py",
                "name": "pip/example.py",
                "hashes": [
                    {"alg": "SHA-256", "content": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
                ],
                "properties": [{"name": "size", "value": "3"}],
            }
        ],
    }


def test_bundled_wheel_scope(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    bundle_wheel({})
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    assert json.loads(build_sbom(config))["metadata"]["properties"] == [
        {
            "name": "example:sbom:scope",
            "value": "Components are the wheels bundled as data files under src/example/wheels and the direct runtime"
            " dependencies declared in the wheel's core metadata. The latter carry no version because they are"
            " resolved at install time, not at build time.",
        }
    ]


def test_bundled_wheels_sorted_and_first(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    bundle_wheel({}, name="setuptools")
    bundle_wheel({}, name="pip")
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED, "src/example/wheels/pip-*"]}
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    assert document["dependencies"][0]["dependsOn"] == [
        "pkg:pypi/pip@1.0",
        "pkg:pypi/setuptools@1.0",
        "requires-dist:packaging>=24",
        "requires-dist:tomli>=2; python_version < '3.11'",
    ]


@pytest.mark.parametrize(
    ("source", "urls", "expected"),
    [
        pytest.param("https://github.com/example/pip", _URLS, True, id="same-account"),
        pytest.param("https://github.com/other/pip", _URLS, False, id="other-account"),
        pytest.param("https://github.com/example/pip", {}, False, id="no-repository"),
    ],
)
def test_bundled_wheel_supplier(
    build_sbom: Callable[[dict[str, Any]], str],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
    source: str,
    urls: dict[str, str],
    expected: bool,
) -> None:
    bundle_wheel({}, f"Project-URL: Source, {source}\n")
    config["project"]["urls"] = urls
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {
        "bundled-wheels": [_BUNDLED],
        "supplier": {"name": "Example Org"},
    }
    assert ("supplier" in json.loads(build_sbom(config))["components"][0]) is expected


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param("pip/example.py", id="plain"),
        pytest.param("pip/a,b.py", id="comma"),
        pytest.param('pip/a"b.py', id="quote"),
        pytest.param("pip/a\nb.py", id="newline"),
    ],
)
def test_bundled_wheel_record_paths(
    root: Path, build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any], filename: str
) -> None:
    record: Final[StringIO] = StringIO(newline="")
    csv.writer(record).writerows([
        (filename, "sha256=ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", "3"),
        ("pip-1.0.dist-info/RECORD", "", ""),
    ])
    (wheels := root / "src" / "example" / "wheels").mkdir(parents=True)
    with zipfile.ZipFile(wheels / "pip-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("pip-1.0.dist-info/METADATA", "Metadata-Version: 2.4\nName: pip\nVersion: 1.0\n")
        archive.writestr("pip-1.0.dist-info/RECORD", record.getvalue())
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    assert json.loads(build_sbom(config))["components"][0]["components"] == [
        {
            "type": "file",
            "bom-ref": f"pkg:pypi/pip@1.0#{filename}",
            "name": filename,
            "hashes": [
                {"alg": "SHA-256", "content": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
            ],
            "properties": [{"name": "size", "value": "3"}],
        },
    ]


@pytest.mark.parametrize(
    ("source", "content"),
    [
        pytest.param(
            "pip/_vendor/vendor.txt", "# bundled\n\n  urllib3==1.26.4 # patched upstream\n", id="pip-manifest"
        ),
        pytest.param(
            "pip/_vendor/urllib3-1.26.4.dist-info/METADATA", "Name: urllib3\nVersion: 1.26.4\n", id="nested-metadata"
        ),
    ],
)
def test_vendored_identity(
    build_sbom: Callable[[dict[str, Any]], str],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
    source: str,
    content: str,
) -> None:
    bundle_wheel({source: content})
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    assert [child for child in document["components"][0]["components"] if child["type"] == "library"] == [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/pip@1.0#vendored/pkg:pypi/urllib3@1.26.4",
            "name": "urllib3",
            "version": "1.26.4",
            "purl": "pkg:pypi/urllib3@1.26.4",
            "externalReferences": [],
            "properties": [{"name": "example:vendored-manifest", "value": source}],
            "evidence": {
                "identity": [
                    {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": source}],
                    }
                ]
            },
        }
    ]


def test_vendored_relationship(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"})
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    assert json.loads(build_sbom(config))["dependencies"][1] == {
        "ref": "pkg:pypi/pip@1.0",
        "dependsOn": ["pkg:pypi/pip@1.0#vendored/pkg:pypi/urllib3@1.26.4"],
    }


def test_vendored_metadata_precedence(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    bundle_wheel({
        "pip/_vendor/vendor.txt": "urllib3==1.26.4\n",
        "pip/_vendor/urllib3-1.26.4.dist-info/METADATA": "Name: urllib3\nVersion: 1.26.4\nLicense-Expression: MIT\n",
    })
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    assert [child["licenses"] for child in document["components"][0]["components"] if child["type"] == "library"] == [
        [{"expression": "MIT", "acknowledgement": "declared"}],
    ]


@pytest.mark.parametrize(
    "requirement",
    [
        pytest.param("urllib3", id="missing"),
        pytest.param("urllib3>=1", id="range"),
        pytest.param("urllib3==1.*", id="wildcard"),
        pytest.param("urllib3 @ https://example.com/package.whl", id="url"),
    ],
)
def test_vendored_unpinned_rejected(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any], requirement: str
) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": requirement})
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    with pytest.raises(ValueError, match="Unpinned vendored dependency"):
        build_sbom(config)


@pytest.mark.parametrize(
    ("metadata", "expected"),
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
            "Classifier: License :: OSI Approved :: Python Software Foundation License\nLicense: PSF-2.0\n",
            [
                {"license": {"name": "Python Software Foundation License", "acknowledgement": "declared"}},
                {"license": {"name": "PSF-2.0", "acknowledgement": "declared"}},
                {"license": {"id": "PSF-2.0", "acknowledgement": "concluded"}},
            ],
            id="classifier-and-id-agree",
        ),
        pytest.param(
            "License: mit\n",
            [
                {"license": {"name": "mit", "acknowledgement": "declared"}},
                {"license": {"id": "MIT", "acknowledgement": "concluded"}},
            ],
            id="id-canonical-case",
        ),
        pytest.param(
            "Classifier: License :: OSI Approved :: MIT License\n"
            "Classifier: License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)\n",
            [
                {"license": {"name": "MIT License", "acknowledgement": "declared"}},
                {"license": {"name": "GNU Lesser General Public License v3 (LGPLv3)", "acknowledgement": "declared"}},
            ],
            id="one-unresolved",
        ),
        pytest.param(
            "License: MIT OR Apache-2.0\n",
            [{"license": {"name": "MIT OR Apache-2.0", "acknowledgement": "declared"}}],
            id="expression-in-license-field",
        ),
        pytest.param(
            "License: LicenseRef-Proprietary\n",
            [{"license": {"name": "LicenseRef-Proprietary", "acknowledgement": "declared"}}],
            id="license-ref",
        ),
    ],
)
def test_license_resolution(
    build_sbom: Callable[[dict[str, Any]], str],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
    metadata: str,
    expected: list[dict[str, Any]],
) -> None:
    bundle_wheel({}, metadata)
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    assert json.loads(build_sbom(config))["components"][0]["licenses"] == expected


def test_bundled_wheel_metadata_fields(
    build_sbom: Callable[[dict[str, Any]], str], bundle_wheel: BundleWheel, config: dict[str, Any]
) -> None:
    bundle_wheel(
        {},
        "Summary: installer\nHome-page: https://pip.pypa.io\nAuthor: Someone\nAuthor-email: dev@example.com\n"
        "Maintainer-email: Team <>\nProject-URL: Bug Tracker, https://example.com/issues\n",
    )
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = {"bundled-wheels": [_BUNDLED]}
    component: Final[dict[str, Any]] = json.loads(build_sbom(config))["components"][0]
    assert {key: component[key] for key in ("description", "authors", "externalReferences")} == {
        "description": "installer",
        "authors": [{"name": "Someone"}, {"email": "dev@example.com"}, {"name": "Team"}],
        "externalReferences": [
            {"type": "website", "url": "https://pip.pypa.io"},
            {"type": "issue-tracker", "url": "https://example.com/issues", "comment": "Project-URL: Bug Tracker"},
            {"type": "distribution", "url": "https://pypi.org/project/pip/1.0/"},
        ],
    }


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        pytest.param({}, ("2020-02-02T00:00:00+00:00", "1580601600"), id="hatchling-default"),
        pytest.param(
            {"SOURCE_DATE_EPOCH": "1700000000"}, ("2023-11-14T22:13:20+00:00", "1700000000"), id="source-date-epoch"
        ),
    ],
)
def test_timestamp(
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    mocker: MockerFixture,
    environment: dict[str, str],
    expected: tuple[str, str],
) -> None:
    mocker.patch.dict(os.environ, environment)
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    workflow: Final[dict[str, Any]] = document["formulation"][0]["workflows"][0]
    assert (document["metadata"]["timestamp"], workflow["inputs"][0]["environmentVars"][0]["value"]) == expected


def test_build_host_independent(
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    install_tool: InstallTool,
    mocker: MockerFixture,
    tmp_path: Path,
) -> None:
    sboms: Final[list[str]] = []
    for host, extension, installer, sys_version in (
        (
            {
                "system": "Linux",
                "release": "6.17.0-1022-azure",
                "version": "#22~24.04.1-Ubuntu SMP",
                "machine": "x86_64",
                "platform": "Linux-6.17.0-1022-azure-x86_64-with-glibc2.39",
                "python_compiler": "GCC 13.3.0",
                "python_build": ("main", "Aug  5 2026 10:00:00"),
            },
            "cpython-314-x86_64-linux-gnu.so",
            b"uv\n",
            "3.14.7 (main, Aug  5 2026, 10:00:00) [GCC 13.3.0]",
        ),
        (
            {
                "system": "Linux",
                "release": "7.0.12-linuxkit",
                "version": "#1 SMP PREEMPT",
                "machine": "aarch64",
                "platform": "Linux-7.0.12-linuxkit-aarch64-with-glibc2.36",
                "python_compiler": "Clang 20.1.4",
                "python_build": ("main", "Sep  1 2026 08:00:00"),
            },
            "cpython-314-aarch64-linux-gnu.so",
            b"pip\n",
            "3.14.7 (main, Sep  1 2026, 08:00:00) [Clang 20.1.4]",
        ),
    ):
        for name, value in host.items():
            mocker.patch(f"platform.{name}", autospec=True, return_value=value)
        mocker.patch.object(sys, "version", sys_version)
        install_tool(site := tmp_path / extension, "native", False, {f"native/_speedups.{extension}": b"\0"})
        install_tool(site, "pure", True, {"pure-1.0.dist-info/INSTALLER": installer, "pure/__init__.py": b""})
        mocker.patch.object(sys, "path", [str(site), *sys.path])
        sboms.append(build_sbom(config))
        mocker.stopall()
    assert sboms[0] == sboms[1]


def test_build_tools_pure_files(
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    install_tool: InstallTool,
    mocker: MockerFixture,
    tmp_path: Path,
) -> None:
    install_tool(
        site := tmp_path / "site",
        "pure",
        True,
        {"pure-1.0.dist-info/INSTALLER": b"uv\n", "pure/__init__.py": b"", "../../bin/pure": b"#!python\n"},
    )
    install_tool(site, "native", False, {"native/_speedups.so": b"\0"})
    mocker.patch.object(sys, "path", [str(site), *sys.path])
    tools: Final[dict[str, dict[str, Any]]] = {
        tool["name"]: tool for tool in json.loads(build_sbom(config))["metadata"]["tools"]["components"]
    }
    assert ([file["name"] for file in tools["pure"]["components"]], "components" in tools["native"]) == (
        ["pure/__init__.py"],
        False,
    )


def test_ci_rerun(
    build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "100")
    first: Final[str] = build_sbom(config)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "200")
    assert build_sbom(config) == first


def test_source_revision(
    root: Path, build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.setenv(name, "Example")
    for name in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(name, "example@example.com")
    for command in (["init", "-q"], ["add", "."], ["commit", "-q", "--no-gpg-sign", "-m", "init"]):
        subprocess.run(["git", *command], cwd=root, check=True)
    commit: Final[str] = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    component: Final[dict[str, Any]] = json.loads(build_sbom(config))["metadata"]["component"]
    assert (component["externalReferences"][-1], component["properties"][-1]) == (
        {"type": "vcs", "url": f"https://github.com/example/example/tree/{commit}", "comment": "exact source revision"},
        {"name": "example:vcs-commit", "value": commit},
    )


def test_source_revision_without_repository(
    root: Path, build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any], mocker: MockerFixture
) -> None:
    (root / ".git").mkdir()
    mocker.patch(
        "subprocess.run",
        autospec=True,
        return_value=subprocess.CompletedProcess(["git"], 0, stdout="c0ffee\n", stderr=""),
    )
    del config["project"]["urls"]
    component: Final[dict[str, Any]] = json.loads(build_sbom(config))["metadata"]["component"]
    assert ([ref["type"] for ref in component["externalReferences"]], component["properties"][-1]) == (
        ["distribution", "attestation"],
        {"name": "example:vcs-commit", "value": "c0ffee"},
    )


def test_source_revision_unreadable(
    root: Path,
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (root / ".git").mkdir()
    mocker.patch(
        "subprocess.run",
        autospec=True,
        side_effect=subprocess.CalledProcessError(128, ["git"], stderr="fatal: detected dubious ownership"),
    )
    component: Final[dict[str, Any]] = json.loads(build_sbom(config))["metadata"]["component"]
    assert (
        [prop["name"] for prop in component["properties"]],
        "names no source revision: fatal: detected dubious ownership" in capsys.readouterr().err,
    ) == (["example:requires-python", "python:classifier", "python:keyword"], True)


@pytest.mark.parametrize(
    ("hook_config", "expected"),
    [
        pytest.param(
            {"repository": "https://gitlab.com/example/example/"},
            [
                {"type": "release-notes", "url": "https://example.com/changelog", "comment": "Project-URL: Changelog"},
                {"type": "vcs", "url": "https://github.com/example/example", "comment": "Project-URL: Source"},
                {"type": "distribution", "url": "https://pypi.org/project/example/1.0/"},
                {"type": "license", "url": "https://gitlab.com/example/example/blob/main/LICENSE"},
            ],
            id="repository-off-github",
        ),
        pytest.param(
            {"default-branch": "trunk"},
            [
                {"type": "release-notes", "url": "https://example.com/changelog", "comment": "Project-URL: Changelog"},
                {"type": "vcs", "url": "https://github.com/example/example", "comment": "Project-URL: Source"},
                {"type": "distribution", "url": "https://pypi.org/project/example/1.0/"},
                {"type": "security-contact", "url": "https://github.com/example/example/security/policy"},
                {"type": "advisories", "url": "https://github.com/example/example/security/advisories"},
                {"type": "license", "url": "https://github.com/example/example/blob/trunk/LICENSE"},
            ],
            id="default-branch",
        ),
    ],
)
def test_repository_links(
    build_sbom: Callable[[dict[str, Any]], str],
    config: dict[str, Any],
    hook_config: dict[str, Any],
    expected: list[dict[str, str]],
) -> None:
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = hook_config
    references: Final[list[dict[str, str]]] = json.loads(build_sbom(config))["metadata"]["component"][
        "externalReferences"
    ]
    assert [reference for reference in references if reference["type"] != "attestation"] == expected


def test_serial_number_per_project(build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any]) -> None:
    first: Final[str] = json.loads(build_sbom(config))["serialNumber"]
    del config["project"]["urls"]
    assert json.loads(build_sbom(config))["serialNumber"] != first


@pytest.mark.parametrize(
    ("build_data", "tag"),
    [
        pytest.param({"tag": "py3-none-linux_x86_64"}, "py3-none-linux_x86_64", id="set-by-another-hook"),
        pytest.param({"infer_tag": True}, None, id="inferred"),
    ],
)
def test_attestation_wheel_tag(root: Path, config: dict[str, Any], build_data: dict[str, Any], tag: str | None) -> None:
    builder: Final[WheelBuilder] = WheelBuilder(str(root), config=config)
    data: Final[dict[str, Any]] = {**builder.get_default_build_data(), "sbom_files": [], **build_data}
    (hook,) = builder.get_build_hooks(str(root / "dist")).values()
    hook.initialize("standard", data)
    references: Final[list[dict[str, str]]] = json.loads(Path(data["sbom_files"][0]).read_text(encoding="utf-8"))[
        "metadata"
    ]["component"]["externalReferences"]
    expected: Final[str] = tag or builder.get_best_matching_tag()
    assert [ref["url"] for ref in references if ref["type"] == "attestation"] == [
        f"https://pypi.org/integrity/example/1.0/example-1.0-{expected}.whl/provenance"
    ]


def test_finalize_removes_sbom(root: Path, config: dict[str, Any]) -> None:
    builder: Final[WheelBuilder] = WheelBuilder(str(root), config=config)
    build_data: Final[dict[str, Any]] = {**builder.get_default_build_data(), "sbom_files": []}
    (hook,) = builder.get_build_hooks(str(root / "dist")).values()
    hook.initialize("standard", build_data)
    hook.finalize("standard", build_data, "")
    assert Path(build_data["sbom_files"][0]).parent.exists() is False


@pytest.mark.parametrize(
    ("hook_config", "message"),
    [
        pytest.param(
            {"supplier": "Example"}, "Option `supplier` of build hook `pep770` must be a table", id="supplier"
        ),
        pytest.param({"supplier": {"name": "Example", "email": "x"}}, "Option `supplier`", id="supplier-unknown-key"),
        pytest.param({"repository": 1}, "Option `repository` of build hook `pep770` must be a string", id="repository"),
        pytest.param(
            {"default-branch": 1}, "Option `default-branch` of build hook `pep770` must be a string", id="branch"
        ),
        pytest.param(
            {"bundled-wheels": "*.whl"},
            "Option `bundled-wheels` of build hook `pep770` must be an array of strings",
            id="bundled-wheels",
        ),
    ],
)
def test_invalid_option(
    build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any], hook_config: dict[str, Any], message: str
) -> None:
    config["tool"]["hatch"]["build"]["hooks"]["pep770"] = hook_config
    with pytest.raises(TypeError, match=message):
        build_sbom(config)


@pytest.mark.parametrize(
    ("urls", "references"),
    [
        pytest.param(
            _URLS,
            {
                "externalReferences": [
                    {"type": "vcs", "url": "https://github.com/example/example/blob/main/hatch_build.py"}
                ]
            },
            id="repository",
        ),
        pytest.param({}, {}, id="no-repository"),
    ],
)
def test_custom_hook_subclass(
    root: Path,
    build_sbom: Callable[[dict[str, Any]], str],
    bundle_wheel: BundleWheel,
    config: dict[str, Any],
    urls: dict[str, str],
    references: dict[str, Any],
) -> None:
    bundle_wheel({})
    (script := root / "hatch_build.py").write_text(
        "from __future__ import annotations\n\nfrom hatch_pep770 import plugin\n\n\n"
        "class Hook(plugin.Pep770BuildHook):\n"
        "    def bundled_wheel_properties(self, wheel):\n"
        '        return [{"name": "example:installed-for-python", "value": wheel.name}]\n\n\n'
        "def get_build_hook():\n    return Hook\n",
        encoding="utf-8",
    )
    config["project"]["urls"] = urls
    config["tool"]["hatch"]["build"]["hooks"] = {"custom": {"bundled-wheels": [_BUNDLED]}}
    document: Final[dict[str, Any]] = json.loads(build_sbom(config))
    assert (document["metadata"]["tools"]["components"][0], document["components"][0]["properties"][:2]) == (
        {
            "type": "application",
            "bom-ref": "tool:hatch_build.py",
            "name": "hatch_build.py",
            "version": "1.0",
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(script.read_bytes()).hexdigest()}],
            **references,
        },
        [
            {"name": "example:bundled-wheel", "value": "src/example/wheels/pip-1.0-py3-none-any.whl"},
            {"name": "example:installed-for-python", "value": "pip-1.0-py3-none-any.whl"},
        ],
    )
