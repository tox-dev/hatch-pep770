from __future__ import annotations

import importlib
import json
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from conftest import digest, write_seed_wheel
from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelFile

from python_sbom import Settings, validate_wheel

if TYPE_CHECKING:
    from conftest import EmbedInto, MakeWheel

    from python_sbom import Document

_METADATA: Final[str] = "License-Expression: MIT\nProject-URL: Source, https://github.com/example/native\n"


def test_embed_writes_sbom(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    name: Final[str] = embed_into(wheel)
    with zipfile.ZipFile(wheel) as archive:
        document: Final[Document] = json.loads(archive.read(name))
    assert (name, document["metadata"]["component"]["purl"]) == (
        "native-1.0.dist-info/sboms/native.cdx.json",
        "pkg:pypi/native@1.0",
    )


def test_embed_record(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    name: Final[str] = embed_into(wheel)
    with zipfile.ZipFile(wheel) as archive:
        sbom: Final[bytes] = archive.read(name)
        rows: Final[list[str]] = archive.read("native-1.0.dist-info/RECORD").decode("utf-8").splitlines()
        last: Final[str] = archive.namelist()[-1]
    assert (rows[-2:], last) == (
        [f"{name},{digest(sbom)},{len(sbom)}", "native-1.0.dist-info/RECORD,,"],
        "native-1.0.dist-info/RECORD",
    )


def test_embed_twice_same_bytes(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    embed_into(wheel)
    first: Final[bytes] = wheel.read_bytes()
    embed_into(wheel)
    assert wheel.read_bytes() == first


def test_embed_keeps_entries(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    with zipfile.ZipFile(wheel) as archive:
        before: Final[list[tuple[str, tuple[int, ...]]]] = [
            (info.filename, info.date_time) for info in archive.infolist()
        ]
    embed_into(wheel)
    with zipfile.ZipFile(wheel) as archive:
        after: Final[list[tuple[str, tuple[int, ...]]]] = [
            (info.filename, info.date_time) for info in archive.infolist()
        ]
    assert after == [*before[:-1], ("native-1.0.dist-info/sboms/native.cdx.json", (2020, 2, 2, 0, 0, 0)), before[-1]]


def test_embed_crlf_record(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    with zipfile.ZipFile(wheel) as archive:
        entries: Final[dict[str, bytes]] = {name: archive.read(name) for name in archive.namelist()}
    entries["native-1.0.dist-info/RECORD"] = entries["native-1.0.dist-info/RECORD"].replace(b"\n", b"\r\n")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    name: Final[str] = embed_into(wheel)
    with zipfile.ZipFile(wheel) as archive:
        record: Final[bytes] = archive.read("native-1.0.dist-info/RECORD")
    assert (record.count(b"\r\n"), record.count(b"\n"), f"{name},".encode() in record) == (5, 5, True)


def test_embed_valid(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    embed_into(wheel)
    assert validate_wheel(wheel, frozenset({"MIT"})) == []


def test_embed_survives_install(make_wheel: MakeWheel, embed_into: EmbedInto, tmp_path: Path) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    name: Final[str] = embed_into(wheel)
    scheme: Final[dict[str, str]] = {
        key: str(tmp_path / "site" / key) for key in ("purelib", "platlib", "headers", "scripts", "data")
    }
    with WheelFile.open(wheel) as source:
        source.validate_record()
        install(source, SchemeDictionaryDestination(scheme, sys.executable, "posix"), {})
    assert (Path(scheme["platlib"]) / name).is_file()


def test_embed_uses_project_settings(make_wheel: MakeWheel, embed_into: EmbedInto) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    settings: Final[Settings] = Settings.from_table({"supplier": {"name": "Org"}}, "[tool.python-sbom]")
    name: Final[str] = embed_into(wheel, settings)
    with zipfile.ZipFile(wheel) as archive:
        document: Final[Document] = json.loads(archive.read(name))
    assert document["metadata"].get("supplier") == {"name": "Org", "url": []}


def test_embed_bundled_wheel(make_wheel: MakeWheel, embed_into: EmbedInto, tmp_path: Path) -> None:
    wheel: Final[Path] = make_wheel(_METADATA)
    write_seed_wheel(tmp_path)
    settings: Final[Settings] = Settings.from_table({"bundled-wheels": ["*.whl"]}, "[tool.python-sbom]")
    name: Final[str] = embed_into(wheel, settings)
    with zipfile.ZipFile(wheel) as archive:
        document: Final[Document] = json.loads(archive.read(name))
    assert document["components"][0].get("properties") == [
        {"name": "native:bundled-wheel", "value": "pip-1.0-py3-none-any.whl"}
    ]


@pytest.fixture
def without_hatchling(monkeypatch: pytest.MonkeyPatch) -> None:
    # a fresh import of the package with hatchling unimportable, as for a project built with another backend
    for name in [name for name in sys.modules if name.split(".")[0] in {"python_sbom", "hatchling"}]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "hatchling", None)


@pytest.mark.usefixtures("without_hatchling")
def test_embed_without_hatchling(make_wheel: MakeWheel, tmp_path: Path) -> None:
    core = importlib.import_module("python_sbom")
    wheel: Final[Path] = make_wheel(_METADATA)
    facts = core.BuildFacts.collect(tmp_path, core.git_revision)
    name: Final[str] = core.BuiltWheel(wheel, tmp_path, core.Settings.from_table({}, "[tool.python-sbom]")).embed(facts)
    assert (name, "hatchling" in {module.split(".")[0] for module in sys.modules if sys.modules[module]}) == (
        "native-1.0.dist-info/sboms/native.cdx.json",
        False,
    )
