from __future__ import annotations

import json
import stat
import zipfile
from typing import TYPE_CHECKING

import pytest

from python_sbom._cli._main import main

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def zipapp(tmp_path: Path) -> Path:
    with zipfile.ZipFile(target := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("__main__.py", "import app\n")
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\nLicense-Expression: MIT\n")
        handle.writestr("app/__init__.py", "")
    return target


def test_archive_writes_sbom_next_to_archive(project: Path, zipapp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["archive", str(zipapp), "--root", str(project), "--build-env", str(project)])
    assert (
        capsys.readouterr().out,
        json.loads(zipapp.with_name("app.pyz.cdx.json").read_text())["metadata"]["component"]["name"],
    ) == (
        f"wrote {zipapp.with_name('app.pyz.cdx.json')}\n",
        "app.pyz",
    )


def test_archive_embeds_sbom(project: Path, zipapp: Path, tmp_path: Path) -> None:
    (project / "build_app.py").write_text("", encoding="utf-8")
    main([
        "archive",
        str(zipapp),
        "--root",
        str(project),
        "--build-env",
        str(project),
        "--build-script",
        "build_app.py",
        "--output",
        str(tmp_path / "out.json"),
        "--embed",
    ])
    entry = zipfile.ZipFile(zipapp).getinfo("app.pyz.cdx.json")
    assert (entry.create_system, entry.external_attr, entry.compress_type, zipfile.ZipFile(zipapp).read(entry)) == (
        3,
        (stat.S_IFREG | 0o644) << 16,
        zipfile.ZIP_DEFLATED,
        (tmp_path / "out.json").read_bytes(),
    )


def test_archive_refuses_second_embed(project: Path, zipapp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["archive", str(zipapp), "--root", str(project), "--build-env", str(project), "--embed"]
    main(arguments)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        main(arguments)
    assert capsys.readouterr().err == "python-sbom: app.pyz already holds app.pyz.cdx.json\n"


def test_archive_embed_leaves_no_temporary_files(project: Path, zipapp: Path, temp_dir: Path) -> None:
    main(["archive", str(zipapp), "--root", str(project), "--build-env", str(project), "--embed"])
    # the rewritten archive is staged next to the original
    assert (list(temp_dir.iterdir()), sorted(path.name for path in zipapp.parent.iterdir())) == (
        [],
        ["app.pyz", "app.pyz.cdx.json", "project", "temp"],
    )
