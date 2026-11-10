from __future__ import annotations

import json
import tracemalloc
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import SbomError
from python_sbom._formats._json import dumps
from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from collections.abc import Callable
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


def test_cargo_cyclonedx_sbom_is_checked(tmp_path: Path, write_wheel: WriteWheel) -> None:
    # maturin names the SBOM of a wheel's Rust crates the way cargo-cyclonedx does
    repeated = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "name": "a", "bom-ref": "a"},
            {"type": "library", "name": "b", "bom-ref": "a"},
        ],
    }
    wheel = write_wheel(
        tmp_path / "example-1.0-py3-none-any.whl",
        {**_METADATA, "example-1.0.dist-info/sboms/example.cyclonedx.json": json.dumps(repeated).encode()},
    )
    assert validate(wheel, None) == ["example-1.0.dist-info/sboms/example.cyclonedx.json: bom-ref values repeat: a"]


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


def test_oversized_sbom_is_reported_and_the_rest_checked(tmp_path: Path, write_wheel: WriteWheel) -> None:
    # 64 MiB of whitespace compresses to a few KiB; reading stops past the 1,058,816 bytes ten components allow
    sboms = {
        "example-1.0.dist-info/sboms/big.cdx.json": b" " * (64 * 1024 * 1024),
        "example-1.0.dist-info/sboms/small.cdx.json": b"not JSON",
    }
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", {**_METADATA, **sboms})
    problems, peak = traced(lambda: validate(wheel, None, max_components=10))
    assert problems == [
        (
            "example-1.0.dist-info/sboms/big.cdx.json: is over 1058816 bytes, the size limit for 10 components;"
            " pass a higher --max-components to check it"
        ),
        "example-1.0.dist-info/sboms/small.cdx.json: is not JSON: Expecting value: line 1 column 1 (char 0)",
    ]
    assert peak < 8 * 1024 * 1024


def traced(run: Callable[[], list[str]]) -> tuple[list[str], int]:
    tracemalloc.start()
    try:
        result = run()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


def test_sboms_are_held_one_at_a_time(tmp_path: Path, write_wheel: WriteWheel) -> None:
    # each compresses to a few KiB, so a small wheel packs many SBOMs that together decompress to 64 MiB
    sboms = {f"example-1.0.dist-info/sboms/x{index:02}.cdx.json": b" " * (2 * 1024 * 1024) for index in range(32)}
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", {**_METADATA, **sboms}, record=False)
    problems, peak = traced(lambda: validate(wheel, None))
    assert problems == [
        f"{name}: is not JSON: Expecting value: line 1 column 2097153 (char 2097152)" for name in sorted(sboms)
    ]
    assert peak < 16 * 1024 * 1024


def test_oversized_json_file(tmp_path: Path) -> None:
    (sbom := tmp_path / "example.cdx.json").write_bytes(b" " * 1_058_817)
    assert validate(sbom, None, max_components=10) == [
        "is over 1058816 bytes, the size limit for 10 components; pass a higher --max-components to check it"
    ]


def test_sbom_not_utf8_is_reported_and_the_rest_checked(tmp_path: Path, write_wheel: WriteWheel) -> None:
    sboms = {
        "example-1.0.dist-info/sboms/utf16.cdx.json": b"\xff\xfe{}",
        "example-1.0.dist-info/sboms/other.cdx.json": b"not JSON",
    }
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", {**_METADATA, **sboms})
    assert validate(wheel, None) == [
        "example-1.0.dist-info/sboms/other.cdx.json: is not JSON: Expecting value: line 1 column 1 (char 0)",
        "example-1.0.dist-info/sboms/utf16.cdx.json: is not UTF-8: invalid start byte at byte 0",
    ]


def test_archive_with_duplicate_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example.cdx.json", b"{}")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("example.cdx.json", b"{}")
    with pytest.raises(SbomError, match=r"holds more than one member named example\.cdx\.json"):
        validate(wheel, None)


def test_corrupt_archive(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("example.cdx.json", b"{}" * 1000)
    data = bytearray(wheel.read_bytes())
    data[40:50] = b"\xff" * 10
    wheel.write_bytes(bytes(data))
    with pytest.raises(SbomError, match=r"example-1\.0-py3-none-any\.whl is not a valid zip archive"):
        validate(wheel, None)


def test_json_file(tmp_path: Path, describe: Describe) -> None:
    (sbom := tmp_path / "example.cdx.json").write_bytes(dumps(describe()))
    assert validate(sbom, frozenset({"MIT"})) == []


def test_json_file_component_cap(tmp_path: Path) -> None:
    components = [{"type": "library", "name": name} for name in ("one", "two", "three")]
    (sbom := tmp_path / "example.cdx.json").write_text(json.dumps({"components": components}), encoding="utf-8")
    assert validate(sbom, None, max_components=2) == [
        "lists more than 2 components, nested ones included; pass a higher --max-components to check it"
    ]
