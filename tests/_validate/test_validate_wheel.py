from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

from python_sbom import dumps, validate_wheel

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Describe, WriteWheel

_METADATA: Final[dict[str, bytes]] = {"example-1.0.dist-info/METADATA": b"Name: Example\nVersion: 1.0\n"}


def test_wheel_without_sbom(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(tmp_path / "example-1.0-py3-none-any.whl", _METADATA)
    assert validate_wheel(wheel, None) == ["no .dist-info/sboms/*.cdx.json found in the wheel"]


def test_every_sbom_is_checked(tmp_path: Path, write_wheel: WriteWheel, describe: Describe) -> None:
    # the schema makes the serial optional, so the loaded JSON, not the typed document, loses it
    broken = json.loads(dumps(describe()))
    del broken["serialNumber"]
    wheel = write_wheel(
        tmp_path / "example-1.0-py3-none-any.whl",
        {
            **_METADATA,
            "example-1.0.dist-info/sboms/example.cdx.json": json.dumps(broken).encode(),
            "example-1.0.dist-info/sboms/other.cdx.json": json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
            }).encode(),
            "example-1.0.dist-info/sboms/notes.txt": b"not an SBOM",
        },
    )
    assert validate_wheel(wheel, None) == [
        "example-1.0.dist-info/sboms/example.cdx.json: serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"
    ]
