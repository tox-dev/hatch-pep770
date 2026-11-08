from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._cli._main import main

if TYPE_CHECKING:
    from pathlib import Path

    from python_sbom._model._types import Document
    from tests.conftest import Install

_SBOM: Final[str] = "native-1.0.dist-info/sboms/native.cdx.json"


_COMMIT: Final[str] = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"


@pytest.fixture
def embed_output(
    project: Path, wheel: Path, tmp_path: Path, install: Install, capsys: pytest.CaptureFixture[str]
) -> str:
    install(site := tmp_path / "site", "Name: meson-python\nVersion: 0.18\n", {})
    main(["embed", str(wheel), "--root", str(project), "--commit", _COMMIT, "--build-env", str(site)])
    return capsys.readouterr().out


def test_embed_reports_the_sbom(embed_output: str, wheel: Path) -> None:
    assert embed_output == f"wrote {_SBOM} into {wheel.name}\n"


@pytest.mark.usefixtures("embed_output")
def test_embed_records_the_commit(wheel: Path) -> None:
    assert {"name": "native:vcs-commit", "value": _COMMIT} in embedded(wheel)["metadata"]["component"]["properties"]


def embedded(wheel: Path) -> Document:
    return json.loads(zipfile.ZipFile(wheel).read(_SBOM))


@pytest.mark.usefixtures("embed_output")
def test_embed_lists_the_build_environment(wheel: Path) -> None:
    assert [tool["name"] for tool in embedded(wheel)["metadata"]["tools"]["components"][1:]] == ["meson-python"]


def test_embed_defaults_to_current_directory(project: Path, wheel: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(project)
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", "cafecafecafecafecafecafecafecafecafecafe")
    main(["embed", str(wheel), "--build-env", str(project)])
    assert {"name": "native:vcs-commit", "value": "cafecafecafecafecafecafecafecafecafecafe"} in embedded(wheel)[
        "metadata"
    ]["component"]["properties"]


@pytest.mark.parametrize(
    ("option", "table"),
    [
        pytest.param(["--content-provider", "MODULE:Native"], "", id="option"),
        pytest.param([], "content-provider = 'MODULE:Native'\n", id="setting"),
    ],
)
def test_embed_with_content_provider(tmp_path: Path, project: Path, wheel: Path, option: list[str], table: str) -> None:
    # a module name unique to the test, so the import cache never hands over another test's module
    provider = """\
from python_sbom import ContentProvider, Contributions


class Native(ContentProvider):
    def contributions(self, context):
        return Contributions(
            root_properties=[{"name": "extra:by", "value": "cli"}]
        )
"""
    (project / f"{tmp_path.name}.py").write_text(provider, encoding="utf-8")
    (project / "pyproject.toml").write_text(f"[tool.python-sbom]\n{table.replace('MODULE', tmp_path.name)}")
    main([
        "embed",
        str(wheel),
        "--root",
        str(project),
        "--build-env",
        str(project),
        *(argument.replace("MODULE", tmp_path.name) for argument in option),
    ])
    document = embedded(wheel)
    assert {"name": "extra:by", "value": "cli"} in document["metadata"]["component"]["properties"]
    assert document["metadata"]["tools"]["components"][0]["name"] == f"{tmp_path.name}.py"


def test_embed_leaves_no_temporary_files(project: Path, wheel: Path, temp_dir: Path) -> None:
    main(["embed", str(wheel), "--root", str(project), "--build-env", str(project)])
    # the rewritten wheel is staged next to the original
    assert (list(temp_dir.iterdir()), list(wheel.parent.iterdir())) == ([], [wheel])
