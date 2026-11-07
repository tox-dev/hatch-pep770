from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._errors import WheelError
from python_sbom._formats._json import dumps
from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Describe, WriteWheel

_METADATA: Final[dict[str, bytes]] = {"example-1.0.dist-info/METADATA": b"Name: Example\nVersion: 1.0\n"}


def test_archive_without_sbom(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", _METADATA)
    assert validate(wheel, None) == ["no SBOM found in example-1.0-py3-none-any.whl"]


def test_every_sbom_is_checked(tmp_path: Path, write_wheel: WriteWheel, describe: Describe) -> None:
    # the schema makes the serial optional, so the loaded JSON, not the typed document, loses it
    broken = json.loads(dumps(describe()))
    del broken["serialNumber"]
    foreign = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}).encode()
    wheel = write_wheel(
        tmp_path / "example-1.0-py3-none-any.whl",
        {
            **_METADATA,
            "example-1.0.dist-info/sboms/example.cdx.json": json.dumps(broken).encode(),
            "example-1.0.dist-info/sboms/other.cdx.json": foreign,
            "example-1.0.dist-info/sboms/notes.txt": b"not an SBOM",
            "app.pyz.cdx.json": foreign,
            "example/nested.cdx.json": json.dumps(broken).encode(),
            "example/sboms/nested.cdx.json": json.dumps(broken).encode(),
        },
    )
    assert validate(wheel, None) == [
        "example-1.0.dist-info/sboms/example.cdx.json: serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"
    ]


def test_sbom_of_every_dist_info_is_checked(tmp_path: Path, write_wheel: WriteWheel, describe: Describe) -> None:
    # a decoy .dist-info sorting first must not hide the SBOM of the wheel's own one
    broken = json.loads(dumps(describe()))
    del broken["serialNumber"]
    wheel = write_wheel(
        tmp_path / "example-1.0-py3-none-any.whl",
        {
            "aaa-0.dist-info/METADATA": b"Name: aaa\nVersion: 0\n",
            "aaa-0.dist-info/sboms/aaa.cdx.json": dumps(describe()),
            **_METADATA,
            "example-1.0.dist-info/sboms/example.cdx.json": json.dumps(broken).encode(),
        },
        record=False,
    )
    assert validate(wheel, None) == [
        "example-1.0.dist-info/sboms/example.cdx.json: serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"
    ]


def test_oversized_sbom(tmp_path: Path, write_wheel: WriteWheel) -> None:
    sbom = b" " * (64 * 1024 * 1024 + 1)
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", {**_METADATA, "example.cdx.json": sbom})
    with pytest.raises(WheelError, match=r"example\.cdx\.json is over the 67108864 byte limit"):
        validate(wheel, None)


def test_archive_with_duplicate_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example.cdx.json", b"{}")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("example.cdx.json", b"{}")
    with pytest.raises(WheelError, match=r"holds more than one member named example\.cdx\.json"):
        validate(wheel, None)


def test_corrupt_archive(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("example.cdx.json", b"{}" * 1000)
    data = bytearray(wheel.read_bytes())
    data[40:50] = b"\xff" * 10
    wheel.write_bytes(bytes(data))
    with pytest.raises(WheelError, match=r"example-1\.0-py3-none-any\.whl is not a valid zip archive"):
        validate(wheel, None)


def test_json_file(tmp_path: Path, describe: Describe) -> None:
    (sbom := tmp_path / "example.cdx.json").write_bytes(dumps(describe()))
    assert validate(sbom, frozenset({"MIT"})) == []
