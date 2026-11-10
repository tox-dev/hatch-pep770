from __future__ import annotations

import dataclasses
import io
import json
import zipfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import BundledWheelInfo, ContentProvider, Contributions, ProviderContext, SbomError
from python_sbom._collect._facts import collect_facts
from python_sbom._collect._revision import revision_reader
from python_sbom._generate._archive import describe_archive
from python_sbom._model._inputs import Revision
from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from conftest import WriteWheel

    from python_sbom import Component
    from python_sbom._model._types import Document

_COMMIT: Final[str] = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
_LIBRARY: Final[str] = "__bundled__/distlib-0.4-py3-none-any"
_WHEEL: Final[str] = "app/wheels/pip-1.0-py3-none-any.whl"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_text(
        "[tool.python-sbom]\nsupplier = { name = 'Example Org' }\nrepository = 'https://github.com/example/app'\n",
        encoding="utf-8",
    )
    (root / "build_app.py").write_text("print('build')\n", encoding="utf-8")
    return root


@pytest.fixture
def archive(tmp_path: Path, write_wheel: WriteWheel) -> Path:
    wheel = write_wheel(
        tmp_path / "pip-1.0-py3-none-any.whl",
        {"pip/__init__.py": b"", "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\nLicense-Expression: MIT\n"},
    )
    with zipfile.ZipFile(target := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("__main__.py", "import app\n")
        handle.writestr("loaded.json", json.dumps({_LIBRARY: ["3.14"]}))
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\nLicense-Expression: MIT\n")
        handle.writestr("app/__init__.py", "")
        handle.writestr("app/", "")
        handle.writestr(_WHEEL, wheel.read_bytes())
        handle.writestr(
            f"{_LIBRARY}/distlib-0.4.dist-info/METADATA", "Name: distlib\nVersion: 0.4\nLicense-Expression: MIT\n"
        )
        handle.writestr(f"{_LIBRARY}/distlib/__init__.py", "")
        handle.writestr("app.pyz.cdx.json", "{}")
    return target


@pytest.fixture
def document(project: Path, archive: Path) -> Document:
    facts = collect_facts(project, revision_reader(_COMMIT))
    return describe_archive(
        project, archive, facts=facts, provider=Bundles("loaded.json"), build_scripts=(PurePosixPath("build_app.py"),)
    )


class Bundles(ContentProvider):
    def __init__(self, table: str) -> None:
        self._table = table

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        # reads the archive, as a real provider reads its tables
        loaded = json.loads(context.read(PurePosixPath(self._table)))
        return BundledWheelInfo(
            properties=[{"name": "app:loaded-for", "value": python} for python in loaded.get(str(wheel), [])],
            supplier=context.settings.supplier,
        )

    def contributions(self, context: ProviderContext) -> Contributions:
        zlib: Component = {"type": "library", "bom-ref": "pkg:generic/zlib@1.3", "name": "zlib", "version": "1.3"}
        return Contributions(
            components=[zlib],
            dependencies=[{"ref": "pkg:generic/zlib@1.3", "dependsOn": []}],
            root_properties=[
                {"name": "extra:project", "value": context.root.name},
                {"name": "extra:table", "value": self._table},
            ],
        )


def test_archive_document_validates(document: Document, tmp_path: Path) -> None:
    (sbom := tmp_path / "app.pyz.cdx.json").write_text(json.dumps(document), encoding="utf-8")
    assert validate(sbom, frozenset({"MIT"})) == []


def test_archive_root(document: Document) -> None:
    root = document["metadata"]["component"]
    assert {key: value for key, value in root.items() if key != "components"} == {
        "type": "application",
        "bom-ref": "pkg:generic/app.pyz@1.0",
        "name": "app.pyz",
        "version": "1.0",
        "purl": "pkg:generic/app.pyz@1.0",
        "supplier": {"name": "Example Org", "url": []},
        "externalReferences": [
            {"type": "security-contact", "url": "https://github.com/example/app/security/policy"},
            {"type": "advisories", "url": "https://github.com/example/app/security/advisories"},
            {
                "type": "vcs",
                "url": f"https://github.com/example/app/tree/{_COMMIT}",
                "comment": "exact source revision",
            },
        ],
        "properties": [
            {"name": "extra:project", "value": "project"},
            {"name": "extra:table", "value": "loaded.json"},
            {"name": "app:vcs-commit", "value": _COMMIT},
        ],
    }


def test_archive_of_dirty_checkout(project: Path, archive: Path) -> None:
    # the same provenance a wheel built from a dirty checkout carries, so the commit is not taken for the exact source
    facts = dataclasses.replace(
        collect_facts(project, revision_reader(_COMMIT)), revision=Revision(commit=_COMMIT, dirty=True)
    )
    root = describe_archive(project, archive, facts=facts, provider=None, build_scripts=())["metadata"]["component"]
    assert (root.get("properties", [])[-1], root.get("externalReferences", [])[-1]["comment"]) == (
        {"name": "app:vcs-dirty", "value": "true"},
        "source revision, with uncommitted changes",
    )


def test_archive_loose_files_belong_to_the_archive(document: Document) -> None:
    files = document["metadata"]["component"].get("components", [])
    assert [file["name"] for file in files] == ["__main__.py", "loaded.json"]


def test_archive_project_distribution(document: Document) -> None:
    app = document["components"][0]
    assert [(child["type"], child["name"]) for child in app.get("components", [])] == [
        ("file", "app-1.0.dist-info/METADATA"),
        ("file", "app/__init__.py"),
        ("library", "pip"),
    ]


def test_archive_bundled_wheel(document: Document) -> None:
    pip = document["components"][0].get("components", [])[2]
    assert (pip["bom-ref"], pip.get("supplier"), pip.get("properties", [])[0]) == (
        f"bundled:{_WHEEL}",
        {"name": "Example Org", "url": []},
        {"name": "app:bundled-wheel", "value": _WHEEL},
    )


def test_archive_unpacked_wheel(document: Document) -> None:
    distlib = document["components"][1]
    assert (
        distlib["bom-ref"],
        "supplier" in distlib,
        distlib.get("properties", []),
        [child["name"] for child in distlib.get("components", [])],
    ) == (
        f"bundled:{_LIBRARY}",
        True,
        [{"name": "app:bundled-wheel", "value": _LIBRARY}, {"name": "app:loaded-for", "value": "3.14"}],
        [f"{_LIBRARY}/distlib-0.4.dist-info/METADATA", f"{_LIBRARY}/distlib/__init__.py"],
    )


def test_archive_tools_and_metadata(document: Document) -> None:
    metadata = document["metadata"]
    script = metadata["tools"]["components"][0]
    assert (script["name"], script.get("externalReferences"), metadata.get("properties"), metadata.get("supplier")) == (
        "build_app.py",
        [{"type": "vcs", "url": f"https://github.com/example/app/blob/{_COMMIT}/build_app.py"}],
        [
            {
                "name": "app:sbom:scope",
                "value": "Components are the distributions the archive holds, as wheels or unpacked, each with its"
                " files; the archive's own top-level files sit under the root component.",
            },
            {"name": "app:sbom:file", "value": "app.pyz.cdx.json"},
            {"name": "app:sbom:repository", "value": "https://github.com/example/app"},
        ],
        {"name": "Example Org", "url": []},
    )


def test_archive_contributions(document: Document) -> None:
    assert (document["components"][-1]["name"], document["dependencies"][-1]) == (
        "zlib",
        {"ref": "pkg:generic/zlib@1.3", "dependsOn": []},
    )


def test_archive_defaults(tmp_path: Path, archive: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'app'\n", encoding="utf-8")
    document = describe_archive(
        tmp_path, archive, facts=collect_facts(tmp_path, revision_reader(None)), provider=None, build_scripts=()
    )
    assert ("supplier" in document["metadata"], document["metadata"]["component"].get("properties")) == (False, [])


def test_archive_content_provider_option(tmp_path: Path, archive: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        f"[tool.python-sbom]\ncontent-provider = '{tmp_path.name}:Provider'\n", encoding="utf-8"
    )
    (tmp_path / f"{tmp_path.name}.py").write_text(
        "from python_sbom import ContentProvider\n\n\nclass Provider(ContentProvider):\n    pass\n", encoding="utf-8"
    )
    tools = describe_archive(
        tmp_path, archive, facts=collect_facts(tmp_path, revision_reader(None)), provider=None, build_scripts=()
    )["metadata"]["tools"]["components"]
    assert tools[0]["name"] == f"{tmp_path.name}.py"


def test_archive_without_project_distribution(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        handle.writestr("__main__.py", "")
    (archive := tmp_path / "bare.pyz").write_bytes(buffer.getvalue())
    with pytest.raises(SbomError, match=r"bare\.pyz holds no top-level \.dist-info/METADATA naming the project"):
        describe_archive(
            tmp_path, archive, facts=collect_facts(tmp_path, revision_reader(None)), provider=None, build_scripts=()
        )


def test_archive_asks_provider_in_component_order(project: Path, archive: Path) -> None:
    asked: Final[list[str]] = []

    class Recording(ContentProvider):
        def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
            asked.append(str(wheel))
            return super().bundled_wheel(context, wheel)

    describe_archive(
        project, archive, facts=collect_facts(project, revision_reader(None)), provider=Recording(), build_scripts=()
    )
    assert asked == [_WHEEL, _LIBRARY]


def test_archive_top_level_wheel_belongs_to_the_archive(project: Path, tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(
        tmp_path / "pip-1.0-py3-none-any.whl", {"pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n"}
    )
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\n")
        handle.writestr(wheel.name, wheel.read_bytes())
    root = describe_archive(
        project, archive, facts=collect_facts(project, revision_reader(None)), provider=None, build_scripts=()
    )["metadata"]["component"]
    assert [(child["bom-ref"], child["name"]) for child in root.get("components", [])] == [
        (f"bundled:{wheel.name}", "pip")
    ]


def test_archive_refuses_distributions_sharing_a_directory(project: Path, tmp_path: Path) -> None:
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\n")
        for name in ("bar", "foo"):
            handle.writestr(f"vendor/{name}-1.0.dist-info/METADATA", f"Name: {name}\nVersion: 1.0\n")
    with pytest.raises(SbomError, match=r"app\.pyz holds more than one \.dist-info in vendor/, so their files cannot"):
        describe_archive(
            project, archive, facts=collect_facts(project, revision_reader(None)), provider=None, build_scripts=()
        )


@pytest.mark.parametrize("placement", [pytest.param("", id="top-level"), pytest.param("app/", id="nested")])
def test_archive_bundled_wheel_judged_wherever_it_sits(
    project: Path, tmp_path: Path, write_wheel: WriteWheel, placement: str
) -> None:
    # the license policy and the vendored edges cover a wheel at the archive's top level as they do one nested deeper
    wheel = write_wheel(
        tmp_path / "pip-1.0-py3-none-any.whl",
        {
            "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\nLicense-Expression: GPL-3.0-only\n",
            "pip/_vendor/vendor.txt": b"urllib3==1.26.4\n",
        },
    )
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\nLicense-Expression: MIT\n")
        handle.writestr(f"{placement}{wheel.name}", wheel.read_bytes())
    document = describe_archive(
        project, archive, facts=collect_facts(project, revision_reader(None)), provider=None, build_scripts=()
    )
    (sbom := tmp_path / "app.pyz.cdx.json").write_text(json.dumps(document), encoding="utf-8")
    ref = f"bundled:{placement}{wheel.name}"
    vendoring = [entry["ref"] for entry in document["dependencies"] if entry["ref"].startswith("bundled:")]
    assert (validate(sbom, frozenset({"MIT"})), vendoring) == (
        [f"{ref}: license GPL-3.0-only is outside the allowed licenses ['MIT']"],
        [ref],
    )
