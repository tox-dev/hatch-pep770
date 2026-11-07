from __future__ import annotations

import stat
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import WheelError, embed_sbom

if TYPE_CHECKING:
    from conftest import WriteWheel
    from pytest_mock import MockerFixture

_SBOM: Final[str] = "native-1.0.dist-info/sboms/native.cdx.json"
# the SHA-256 of b"{}\n", urlsafe base64 without padding
_SBOM_ROW: Final[str] = f"{_SBOM},sha256=yj0WO6sFU4GCciYUBWjzvvfqrBh869doeOC2Pp5EI1Y,3"


@pytest.fixture
def wheel(tmp_path: Path, write_wheel: WriteWheel) -> Path:
    return write_wheel(
        tmp_path / "dist" / "native-1.0-py3-none-any.whl",
        {"native/__init__.py": b"", "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\n"},
    )


def test_embed_returns_member_path(wheel: Path) -> None:
    assert embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000) == _SBOM


def test_embed_puts_sbom_before_record(wheel: Path) -> None:
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).namelist() == [
        "native/__init__.py",
        "native-1.0.dist-info/METADATA",
        _SBOM,
        "native-1.0.dist-info/RECORD",
    ]


def test_embed_records_sbom_before_record_row(wheel: Path) -> None:
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    record = zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD").decode().splitlines()
    assert record[-2:] == [_SBOM_ROW, "native-1.0.dist-info/RECORD,,"]


def test_embed_replaces_existing_sbom(wheel: Path) -> None:
    embed_sbom(wheel, "native.cdx.json", b"[]\n", 1_700_000_000)
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read(_SBOM) == b"{}\n"
        assert [
            line for line in archive.read("native-1.0.dist-info/RECORD").decode().splitlines() if "sboms" in line
        ] == [_SBOM_ROW]


def test_embed_keeps_other_entries(wheel: Path) -> None:
    before = {info.filename: (info.date_time, info.external_attr) for info in zipfile.ZipFile(wheel).infolist()}
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    after = {info.filename: (info.date_time, info.external_attr) for info in zipfile.ZipFile(wheel).infolist()}
    assert {name: after[name] for name in before} == before


@pytest.mark.parametrize(
    ("epoch", "date_time"),
    [
        pytest.param(1_700_000_000, (2023, 11, 14, 22, 13, 20), id="epoch"),
        pytest.param(0, (1980, 1, 1, 0, 0, 0), id="before-zip-epoch"),
    ],
)
def test_embed_entry_is_the_same_on_every_system(wheel: Path, epoch: int, date_time: tuple[int, ...]) -> None:
    embed_sbom(wheel, "native.cdx.json", b"{}\n", epoch)
    info = zipfile.ZipFile(wheel).getinfo(_SBOM)
    assert (info.date_time, info.create_system, info.external_attr) == (
        date_time,
        3,
        (stat.S_IFREG | 0o644) << 16,
    )


def test_embed_is_deterministic(tmp_path: Path, write_wheel: WriteWheel) -> None:
    files = {"native/__init__.py": b"", "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\n"}
    first, second = (write_wheel(tmp_path / name / "native-1.0-py3-none-any.whl", files) for name in ("a", "b"))
    for wheel in (first, second):
        embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert first.read_bytes() == second.read_bytes()


def test_embed_keeps_record_line_endings(tmp_path: Path, write_wheel: WriteWheel) -> None:
    record = b"native-1.0.dist-info/METADATA,,\r\nnative-1.0.dist-info/RECORD,,\r\n"
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {"native-1.0.dist-info/METADATA": b"Name: native\n", "native-1.0.dist-info/RECORD": record},
        record=False,
    )
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD") == (
        f"native-1.0.dist-info/METADATA,,\r\n{_SBOM_ROW}\r\nnative-1.0.dist-info/RECORD,,\r\n".encode()
    )


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no POSIX permission bits")
def test_embed_keeps_wheel_permissions(wheel: Path) -> None:
    wheel.chmod(0o640)
    embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert stat.S_IMODE(wheel.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    ("files", "message"),
    [
        pytest.param({"native/__init__.py": b""}, "has no .dist-info/METADATA, so it is not a wheel", id="no-metadata"),
        pytest.param(
            {"native-1.0.dist-info/METADATA": b"Name: native\n"},
            "has no native-1.0.dist-info/RECORD",
            id="no-record",
        ),
    ],
)
def test_embed_refuses_non_wheel(tmp_path: Path, files: dict[str, bytes], message: str) -> None:
    with zipfile.ZipFile(archive := tmp_path / "native.whl", "w") as handle:
        for name, content in files.items():
            handle.writestr(name, content)
    with pytest.raises(WheelError, match=message):
        embed_sbom(archive, "native.cdx.json", b"{}\n", 1_700_000_000)


def test_failed_embed_leaves_wheel_and_no_temporary_file(wheel: Path, mocker: MockerFixture) -> None:
    original = wheel.read_bytes()
    mocker.patch.object(Path, "replace", autospec=True, side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        embed_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert [path.name for path in wheel.parent.iterdir()] == [wheel.name]
    assert wheel.read_bytes() == original
