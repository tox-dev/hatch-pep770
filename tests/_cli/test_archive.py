from __future__ import annotations

import json
import stat
import struct
import zipfile
import zlib
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
        zipfile.ZIP_STORED,
        (tmp_path / "out.json").read_bytes(),
    )


@pytest.mark.parametrize(
    ("flags", "level"),
    [
        pytest.param(0b000, zlib.Z_DEFAULT_COMPRESSION, id="normal"),
        pytest.param(0b010, 9, id="maximum"),
        pytest.param(0b100, 2, id="fast"),
        pytest.param(0b110, 1, id="super-fast"),
    ],
)
def test_archive_embeds_sbom_compressed_as_its_members(project: Path, flagged_app: Path, level: int) -> None:
    main(["archive", str(flagged_app), "--root", str(project), "--build-env", str(project), "--embed"])
    with zipfile.ZipFile(flagged_app) as handle:
        entry = handle.getinfo("app.pyz.cdx.json")
        content = handle.read(entry)
    data = flagged_app.read_bytes()
    name_length, extra_length = struct.unpack("<HH", data[entry.header_offset + 26 : entry.header_offset + 30])
    start = entry.header_offset + 30 + name_length + extra_length
    compressor = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
    assert data[start : start + entry.compress_size] == compressor.compress(content) + compressor.flush()


@pytest.fixture
def flagged_app(tmp_path: Path, flags: int) -> Path:
    with zipfile.ZipFile(app := tmp_path / "app.pyz", "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("__main__.py", "import app\n")
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\n")
    # zipfile clears the option bits it writes, so they go straight into the central directory, where readers take them
    data = bytearray(app.read_bytes())
    for at in (index for index in range(len(data)) if data[index : index + 4] == b"PK\x01\x02"):
        struct.pack_into("<H", data, at + 8, struct.unpack_from("<H", data, at + 8)[0] | flags)
    app.write_bytes(data)
    return app


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
