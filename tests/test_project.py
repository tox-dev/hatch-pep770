from __future__ import annotations

import csv
import hashlib
import shutil
import subprocess
import sys
import zipfile
from io import StringIO
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import BuildSbom, BundleWheel, InstallTool, WriteProject
    from pytest_mock import MockerFixture

    from python_sbom import Component, Document

from conftest import BUNDLED, HOOK, build_hook_sbom

from python_sbom import SourceRevisionError, WheelError

_SHA256_ABC: Final[str] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_root_component(build_sbom: BuildSbom) -> None:
    assert build_sbom()["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "pkg:pypi/example@1.0",
        "authors": [{"name": "Maintainer", "email": "maintainer@example.com"}],
        "name": "Example",
        "version": "1.0",
        "description": "an example",
        "licenses": [{"expression": "MIT", "acknowledgement": "declared"}],
        "copyright": "Copyright (c) 2026 Example",
        "purl": "pkg:pypi/example@1.0",
        "externalReferences": [
            {"type": "release-notes", "url": "https://example.com/changelog", "comment": "Project-URL: Changelog"},
            {"type": "vcs", "url": "https://github.com/example/example", "comment": "Project-URL: Source"},
            {"type": "distribution", "url": "https://pypi.org/project/Example/1.0/"},
            {
                "type": "attestation",
                "url": "https://pypi.org/integrity/Example/1.0/example-1.0-py3-none-any.whl/provenance",
            },
            {"type": "security-contact", "url": "https://github.com/example/example/security/policy"},
            {"type": "advisories", "url": "https://github.com/example/example/security/advisories"},
            {"type": "license", "url": "https://github.com/example/example/blob/main/LICENSE"},
        ],
        "properties": [
            {"name": "example:requires-python", "value": ">=3.11"},
            {"name": "python:classifier", "value": "Programming Language :: Python :: 3"},
            {"name": "python:keyword", "value": "demo"},
            {"name": "python:keyword", "value": "sample"},
        ],
    }


def test_root_component_minimal_metadata(root: Path, build_sbom: BuildSbom) -> None:
    (root / "LICENSE").write_text("MIT terms\n", encoding="utf-8")
    project = '[project]\nname = "example"\nversion = "1.0"\nlicense-files = ["LICENSE"]\nauthors = [{ name = "A" }]\n'
    assert build_sbom(project=project)["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "pkg:pypi/example@1.0",
        "authors": [{"name": "A"}],
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


def test_document_metadata(build_sbom: BuildSbom) -> None:
    metadata = build_sbom()["metadata"]
    assert (metadata["timestamp"], metadata["lifecycles"], metadata.get("authors"), metadata.get("properties")) == (
        "2020-02-02T00:00:00+00:00",
        [{"phase": "build"}],
        [{"name": "Maintainer", "email": "maintainer@example.com"}],
        [
            {
                "name": "example:sbom:scope",
                "value": "Components are the direct runtime dependencies declared in the wheel's core metadata. They"
                " carry no version because they are resolved at install time, not at build time.",
            }
        ],
    )


def test_supplier(build_sbom: BuildSbom) -> None:
    metadata = build_sbom(hook=f'{HOOK}supplier = {{ name = "Org", url = ["https://org.example"] }}\n')["metadata"]
    assert [metadata.get("manufacturer"), metadata.get("supplier"), metadata["component"].get("supplier")] == [
        {"name": "Org", "url": ["https://org.example"]}
    ] * 3


def test_declared_dependencies(build_sbom: BuildSbom) -> None:
    document = build_sbom()
    assert (document["components"], document["dependencies"][0]) == (
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


def test_composition_incomplete(build_sbom: BuildSbom) -> None:
    assert build_sbom()["compositions"] == [{"aggregate": "incomplete", "dependencies": ["pkg:pypi/example@1.0"]}]


def test_build_workflow(build_sbom: BuildSbom) -> None:
    document = build_sbom()
    workflow = document["formulation"][0]["workflows"][0]
    assert {**workflow, "resourceReferences": len(workflow["resourceReferences"])} == {
        "bom-ref": "workflow:wheel-build",
        "uid": "wheel-build",
        "name": "build the wheel and this SBOM",
        "taskTypes": ["build"],
        "resourceReferences": len(document["metadata"]["tools"]["components"]),
        "outputs": [{"type": "artifact", "resource": {"ref": "pkg:pypi/example@1.0"}}],
        "inputs": [{"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": "1580601600"}]}],
    }


def test_bundled_wheel(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    sha256: Final[str] = hashlib.sha256(bundle_wheel({}, "License-Expression: MIT\n").read_bytes()).hexdigest()
    assert build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0] == {
        "type": "library",
        "bom-ref": "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl",
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
                "bom-ref": "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl#pip/example.py",
                "name": "pip/example.py",
                "hashes": [{"alg": "SHA-256", "content": _SHA256_ABC}],
                "properties": [{"name": "size", "value": "3"}],
            }
        ],
    }


def test_bundled_wheel_scope(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel({})
    assert build_sbom(hook=f"{HOOK}{BUNDLED}")["metadata"].get("properties") == [
        {
            "name": "example:sbom:scope",
            "value": "Components are the wheels bundled as data files under src/example/wheels and the direct runtime"
            " dependencies declared in the wheel's core metadata. The latter carry no version because they are"
            " resolved at install time, not at build time.",
        }
    ]


def test_bundled_wheels_sorted_once(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel({}, name="setuptools")
    bundle_wheel({}, name="pip")
    hook = f'{HOOK}bundled-wheels = ["src/example/wheels/*.whl", "src/example/wheels/pip-*"]\n'
    assert build_sbom(hook=hook)["dependencies"][0]["dependsOn"] == [
        "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl",
        "pkg:pypi/setuptools@1.0?file_name=setuptools-1.0-py3-none-any.whl",
        "requires-dist:packaging>=24",
        "requires-dist:tomli>=2; python_version < '3.11'",
    ]


@pytest.mark.parametrize(
    ("source", "urls", "expected"),
    [
        pytest.param("https://github.com/example/pip", "urls.Source = 'https://github.com/example/x'", True, id="same"),
        pytest.param("https://github.com/other/pip", "urls.Source = 'https://github.com/example/x'", False, id="other"),
        pytest.param("https://github.com/example/pip", "", False, id="no-repository"),
    ],
)
def test_bundled_wheel_supplier(
    build_sbom: BuildSbom, bundle_wheel: BundleWheel, source: str, urls: str, expected: bool
) -> None:
    bundle_wheel({}, f"Project-URL: Source, {source}\n")
    project = f'[project]\nname = "example"\nversion = "1.0"\n{urls}\n'
    hook = f'{HOOK}{BUNDLED}supplier = {{ name = "Org" }}\n'
    assert ("supplier" in build_sbom(hook=hook, project=project)["components"][0]) is expected


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param("pip/example.py", id="plain"),
        pytest.param("pip/a,b.py", id="comma"),
        pytest.param('pip/a"b.py', id="quote"),
        pytest.param("pip/a\nb.py", id="newline"),
    ],
)
def test_bundled_wheel_record_paths(root: Path, build_sbom: BuildSbom, filename: str) -> None:
    record: Final[StringIO] = StringIO(newline="")
    csv.writer(record).writerows([(filename, "sha256=ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", "3")])
    (wheels := root / "src" / "example" / "wheels").mkdir(parents=True)
    with zipfile.ZipFile(wheels / "pip-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("pip-1.0.dist-info/METADATA", "Metadata-Version: 2.4\nName: pip\nVersion: 1.0\n")
        archive.writestr("pip-1.0.dist-info/RECORD", f"{record.getvalue()}pip-1.0.dist-info/RECORD,,\n")
    assert build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0].get("components") == [
        {
            "type": "file",
            "bom-ref": f"pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl#{filename}",
            "name": filename,
            "hashes": [{"alg": "SHA-256", "content": _SHA256_ABC}],
            "properties": [{"name": "size", "value": "3"}],
        },
    ]


@pytest.mark.parametrize(
    ("source", "content"),
    [
        pytest.param("pip/_vendor/vendor.txt", "# vendored\n\n  urllib3==1.26.4 # patched\n", id="pip-manifest"),
        pytest.param(
            "pip/_vendor/urllib3-1.26.4.dist-info/METADATA", "Name: urllib3\nVersion: 1.26.4\n", id="nested-metadata"
        ),
    ],
)
def test_vendored_identity(build_sbom: BuildSbom, bundle_wheel: BundleWheel, source: str, content: str) -> None:
    bundle_wheel({source: content})
    children: Final[list[Component]] = build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0].get("components", [])
    assert [child for child in children if child["type"] == "library"] == [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl#vendored/pkg:pypi/urllib3@1.26.4",
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


def test_vendored_relationship(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"})
    assert build_sbom(hook=f"{HOOK}{BUNDLED}")["dependencies"][1] == {
        "ref": "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl",
        "dependsOn": ["pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl#vendored/pkg:pypi/urllib3@1.26.4"],
    }


def test_vendored_metadata_precedence(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel({
        "pip/_vendor/vendor.txt": "urllib3==1.26.4\n",
        "pip/_vendor/urllib3-1.26.4.dist-info/METADATA": "Name: urllib3\nVersion: 1.26.4\nLicense-Expression: MIT\n",
    })
    children: Final[list[Component]] = build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0].get("components", [])
    assert [child.get("licenses") for child in children if child["type"] == "library"] == [
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
def test_vendored_unpinned_rejected(build_sbom: BuildSbom, bundle_wheel: BundleWheel, requirement: str) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": requirement})
    with pytest.raises(ValueError, match="Unpinned vendored dependency"):
        build_sbom(hook=f"{HOOK}{BUNDLED}")


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
    build_sbom: BuildSbom, bundle_wheel: BundleWheel, metadata: str, expected: list[dict[str, dict[str, str]]]
) -> None:
    bundle_wheel({}, metadata)
    assert build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0].get("licenses") == expected


def test_bundled_wheel_metadata_fields(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel(
        {},
        "Summary: installer\nHome-page: https://pip.pypa.io\nAuthor: Someone\nAuthor-email: dev@example.com\n"
        "Maintainer-email: Team <>\nProject-URL: Bug Tracker, https://example.com/issues\n",
    )
    component = build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][0]
    assert (component.get("description"), component.get("authors"), component.get("externalReferences")) == (
        "installer",
        [{"name": "Someone"}, {"email": "dev@example.com"}, {"name": "Team"}],
        [
            {"type": "website", "url": "https://pip.pypa.io"},
            {"type": "issue-tracker", "url": "https://example.com/issues", "comment": "Project-URL: Bug Tracker"},
            {"type": "distribution", "url": "https://pypi.org/project/pip/1.0/"},
        ],
    )


@pytest.mark.parametrize(
    ("epoch", "expected"),
    [
        pytest.param("1580601600", ("2020-02-02T00:00:00+00:00", "1580601600"), id="hatchling-default"),
        pytest.param("1700000000", ("2023-11-14T22:13:20+00:00", "1700000000"), id="source-date-epoch"),
    ],
)
def test_timestamp(
    build_sbom: BuildSbom, monkeypatch: pytest.MonkeyPatch, epoch: str, expected: tuple[str, str]
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    document = build_sbom()
    variables = document["formulation"][0]["workflows"][0]["inputs"][0]["environmentVars"]
    assert (document["metadata"]["timestamp"], variables[0]["value"]) == expected


def test_build_host_independent(write_project: WriteProject, mocker: MockerFixture, install_tool: InstallTool) -> None:
    root = write_project()
    assert _build_on_host(root, mocker, install_tool, ("x86_64", "GCC 13.3.0", b"uv\n")) == _build_on_host(
        root, mocker, install_tool, ("aarch64", "Clang 20.1.4", b"pip\n")
    )


def _build_on_host(
    root: Path, mocker: MockerFixture, install_tool: InstallTool, host: tuple[str, str, bytes]
) -> Document:
    machine, compiler, installer = host
    mocker.patch("platform.machine", autospec=True, return_value=machine)
    mocker.patch("platform.platform", autospec=True, return_value=f"Linux-{machine}")
    mocker.patch("platform.python_compiler", autospec=True, return_value=compiler)
    mocker.patch.object(sys, "version", f"3.14.7 (main) [{compiler}]")
    install_tool(site := root.parent / machine, "native", False, {f"native/_speedups.{machine}.so": b"\0"})
    install_tool(site, "pure", True, {"pure-1.0.dist-info/INSTALLER": installer, "pure/__init__.py": b""})
    mocker.patch.object(sys, "path", [str(site), *sys.path])
    document = build_hook_sbom(root)
    mocker.stopall()
    return document


def test_build_tools_pure_files(
    write_project: WriteProject, mocker: MockerFixture, install_tool: InstallTool, tmp_path: Path
) -> None:
    install_tool(
        site := tmp_path / "site",
        "pure",
        True,
        {"pure-1.0.dist-info/INSTALLER": b"uv\n", "pure/__init__.py": b"", "../../bin/pure": b"#!python\n"},
    )
    install_tool(site, "native", False, {"native/_speedups.so": b"\0"})
    mocker.patch.object(sys, "path", [str(site), *sys.path])
    tools = {tool["name"]: tool for tool in build_hook_sbom(write_project())["metadata"]["tools"]["components"]}
    assert ([file["name"] for file in tools["pure"].get("components", [])], "components" in tools["native"]) == (
        ["pure/__init__.py"],
        False,
    )


def test_ci_environment_ignored(write_project: WriteProject, monkeypatch: pytest.MonkeyPatch) -> None:
    root = write_project()
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    first: Final[Document] = build_hook_sbom(root)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    assert build_hook_sbom(root) == first


def test_source_revision(write_project: WriteProject, monkeypatch: pytest.MonkeyPatch) -> None:
    root = write_project()
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(root / "gitconfig"))
    (root / "gitconfig").write_text("[user]\n\tname = Example\n\temail = example@example.com\n", encoding="utf-8")
    git = shutil.which("git") or "git"
    subprocess.run([git, "init", "-q"], cwd=root, check=True)
    subprocess.run([git, "commit", "-q", "--allow-empty", "--no-gpg-sign", "-m", "init"], cwd=root, check=True)
    commit = subprocess.run([git, "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True)
    component = build_hook_sbom(root)["metadata"]["component"]
    assert (component.get("externalReferences", [])[-1], component.get("properties", [])[-1]) == (
        {
            "type": "vcs",
            "url": f"https://github.com/example/example/tree/{commit.stdout.strip()}",
            "comment": "exact source revision",
        },
        {"name": "example:vcs-commit", "value": commit.stdout.strip()},
    )


def test_source_revision_without_repository(root: Path, build_sbom: BuildSbom, mocker: MockerFixture) -> None:
    (root / ".git").mkdir()
    mocker.patch("subprocess.run", autospec=True, return_value=subprocess.CompletedProcess(["git"], 0, "c0ffee\n", ""))
    component = build_sbom(project='[project]\nname = "example"\nversion = "1.0"\n')["metadata"]["component"]
    assert component.get("properties") == [{"name": "example:vcs-commit", "value": "c0ffee"}]


def test_source_revision_unreadable(root: Path, build_sbom: BuildSbom, mocker: MockerFixture) -> None:
    (root / ".git").mkdir()
    error = subprocess.CalledProcessError(128, ["git"], stderr="fatal: detected dubious ownership")
    mocker.patch("subprocess.run", autospec=True, side_effect=error)
    with pytest.raises(
        SourceRevisionError, match=r"git rev-parse HEAD failed in .*: fatal: detected dubious ownership"
    ):
        build_sbom()


@pytest.mark.parametrize(
    ("hook", "expected"),
    [
        pytest.param(
            f'{HOOK}repository = "https://gitlab.com/example/example/"\n',
            (
                ["release-notes", "vcs", "distribution", "attestation", "license"],
                "https://gitlab.com/example/example/blob/main/LICENSE",
            ),
            id="off-github",
        ),
        pytest.param(
            f'{HOOK}default-branch = "trunk"\n',
            (
                ["release-notes", "vcs", "distribution", "attestation", "security-contact", "advisories", "license"],
                "https://github.com/example/example/blob/trunk/LICENSE",
            ),
            id="default-branch",
        ),
    ],
)
def test_repository_links(build_sbom: BuildSbom, hook: str, expected: tuple[list[str], str]) -> None:
    references = build_sbom(hook=hook)["metadata"]["component"].get("externalReferences", [])
    assert ([reference["type"] for reference in references], references[-1]["url"]) == expected


def test_serial_number_per_project(build_sbom: BuildSbom) -> None:
    assert (
        build_sbom()["serialNumber"]
        != build_sbom(project='[project]\nname = "Example"\nversion = "1.0"\n')["serialNumber"]
    )


@pytest.mark.parametrize(
    ("hook", "message"),
    [
        pytest.param(
            f'{HOOK}supplier = "Org"\n', "`supplier` in build hook `python-sbom` must be a table", id="supplier"
        ),
        pytest.param(f'{HOOK}supplier = {{ name = "Org", email = "x" }}\n', "`supplier`", id="supplier-unknown-key"),
        pytest.param(f"{HOOK}repository = 1\n", "`repository` in build hook `python-sbom` must be a string", id="repo"),
        pytest.param(
            f"{HOOK}default-branch = 1\n", "`default-branch` in build hook `python-sbom` must be", id="branch"
        ),
        pytest.param(f'{HOOK}bundled-wheels = "*.whl"\n', "`bundled-wheels` in build hook `python-sbom`", id="bundled"),
    ],
)
def test_invalid_option(build_sbom: BuildSbom, hook: str, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        build_sbom(hook=hook)


def test_bundled_wheel_variants_unique_refs(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    wheel = bundle_wheel({})
    shutil.copyfile(wheel, wheel.with_name("pip-1.0-py3-none-manylinux_2_17_x86_64.whl"))
    assert [component["bom-ref"] for component in build_sbom(hook=f"{HOOK}{BUNDLED}")["components"][:2]] == [
        "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-any.whl",
        "pkg:pypi/pip@1.0?file_name=pip-1.0-py3-none-manylinux_2_17_x86_64.whl",
    ]


@pytest.mark.parametrize(
    ("requirement", "expected"),
    [
        pytest.param("foo; extra != 'fast'", ["foo"], id="not-an-extra"),
        pytest.param("foo; extra == 'fast' or python_version < '3.12'", ["foo"], id="extra-or-platform"),
        pytest.param("foo; python_version < '3.12' and extra == 'fast'", [], id="platform-and-extra"),
        pytest.param("foo; (extra == 'a' or extra == 'b') and os_name == 'nt'", [], id="grouped-extras"),
        pytest.param("foo; os_name == 'nt'", ["foo"], id="platform-only"),
        pytest.param("foo; 'fast' == extra", [], id="extra-on-the-right"),
    ],
)
def test_runtime_requirements_with_extra_markers(build_sbom: BuildSbom, requirement: str, expected: list[str]) -> None:
    project = f'[project]\nname = "example"\nversion = "1.0"\ndependencies = ["{requirement}"]\n'
    assert [component["name"] for component in build_sbom(project=project)["components"]] == expected


def test_bundled_wheel_without_metadata(root: Path, build_sbom: BuildSbom) -> None:
    (wheels := root / "src" / "example" / "wheels").mkdir(parents=True)
    with zipfile.ZipFile(wheels / "pip-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("pip/__init__.py", "")
    with pytest.raises(WheelError, match=r"pip-1\.0-py3-none-any\.whl has no \.dist-info/METADATA"):
        build_sbom(hook=f"{HOOK}{BUNDLED}")


def test_vendored_requirement_unparsable(build_sbom: BuildSbom, bundle_wheel: BundleWheel) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": "not a requirement!\n"})
    with pytest.raises(WheelError, match="does not parse: not a requirement!"):
        build_sbom(hook=f"{HOOK}{BUNDLED}")
