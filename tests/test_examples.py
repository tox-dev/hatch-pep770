from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

from docs.examples.zipapp import describe_zipapp
from python_sbom import dumps, validate

if TYPE_CHECKING:
    from pathlib import Path


def test_zipapp_example(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'app'\n", encoding="utf-8")
    with zipfile.ZipFile(zipapp := tmp_path / "app.pyz", "w") as archive:
        archive.writestr("__main__.py", "print('hi')\n")
        archive.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\n")
        archive.writestr("app/", "")
    document = describe_zipapp(tmp_path, zipapp)
    assert validate(dumps(document).decode(), None) == []
    assert [file["name"] for file in document["metadata"]["component"].get("components", [])] == [
        "__main__.py",
        "app-1.0.dist-info/METADATA",
    ]
