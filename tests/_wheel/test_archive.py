from __future__ import annotations

import stat
import struct
import sys
import zipfile
from io import BytesIO
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._collect._source import read_bundled_wheel
from python_sbom._errors import WheelError
from python_sbom._wheel._archive import write_sbom

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import WriteWheel

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
    assert write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000) == _SBOM


def test_embed_puts_sbom_before_record(wheel: Path) -> None:
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).namelist() == [
        "native/__init__.py",
        "native-1.0.dist-info/METADATA",
        _SBOM,
        "native-1.0.dist-info/RECORD",
    ]


def test_embed_records_sbom_before_record_row(wheel: Path) -> None:
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    record = zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD").decode().splitlines()
    assert record[-2:] == [_SBOM_ROW, "native-1.0.dist-info/RECORD,,"]


def test_embed_replaces_existing_sbom(wheel: Path) -> None:
    write_sbom(wheel, "native.cdx.json", b"[]\n", 1_700_000_000)
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read(_SBOM) == b"{}\n"
        assert [
            line for line in archive.read("native-1.0.dist-info/RECORD").decode().splitlines() if "sboms" in line
        ] == [_SBOM_ROW]


def test_embed_keeps_other_entries(wheel: Path) -> None:
    before = {info.filename: (info.date_time, info.external_attr) for info in zipfile.ZipFile(wheel).infolist()}
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    after = {info.filename: (info.date_time, info.external_attr) for info in zipfile.ZipFile(wheel).infolist()}
    assert {name: after[name] for name in before} == before


def test_embed_keeps_other_members_compressed_as_they_were(tmp_path: Path) -> None:
    # level 9 over repetitive text gives other bytes than zipfile's default level, so a recompressed member would differ
    with zipfile.ZipFile(wheel := tmp_path / "native-1.0-py3-none-any.whl", "w", compresslevel=9) as handle:
        handle.writestr(
            "native/data.txt", b"".join(b"line %d\n" % number for number in range(5000)), zipfile.ZIP_DEFLATED
        )
        handle.writestr("native-1.0.dist-info/METADATA", b"Name: native\nVersion: 1.0\n")
        handle.writestr("native-1.0.dist-info/RECORD", b"native-1.0.dist-info/RECORD,,\n")
    before = _stored(wheel, "native/data.txt")
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert _stored(wheel, "native/data.txt") == before


def _stored(wheel: Path, name: str) -> bytes:
    with zipfile.ZipFile(wheel) as archive:
        info = archive.getinfo(name)
    data = wheel.read_bytes()
    name_length, extra_length = struct.unpack("<HH", data[info.header_offset + 26 : info.header_offset + 30])
    start = info.header_offset + 30 + name_length + extra_length
    return data[start : start + info.compress_size]


@pytest.mark.parametrize(
    ("epoch", "date_time"),
    [
        pytest.param(1_700_000_000, (2023, 11, 14, 22, 13, 20), id="epoch"),
        pytest.param(0, (1980, 1, 1, 0, 0, 0), id="before-zip-epoch"),
    ],
)
def test_embed_entry_is_the_same_on_every_system(wheel: Path, epoch: int, date_time: tuple[int, ...]) -> None:
    write_sbom(wheel, "native.cdx.json", b"{}\n", epoch)
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
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert first.read_bytes() == second.read_bytes()


def test_embed_keeps_record_line_endings(tmp_path: Path, write_wheel: WriteWheel) -> None:
    record = b"native-1.0.dist-info/METADATA,,\r\nnative-1.0.dist-info/RECORD,,\r\n"
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {"native-1.0.dist-info/METADATA": b"Name: native\n", "native-1.0.dist-info/RECORD": record},
        record=False,
    )
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD") == (
        f"native-1.0.dist-info/METADATA,,\r\n{_SBOM_ROW}\r\nnative-1.0.dist-info/RECORD,,\r\n".encode()
    )


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no POSIX permission bits")
def test_embed_keeps_wheel_permissions(wheel: Path) -> None:  # pragma: win32 no cover
    wheel.chmod(0o640)
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert stat.S_IMODE(wheel.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    ("files", "message"),
    [
        pytest.param(
            {"native/__init__.py": b""},
            r"is not a wheel: Wheel doesn't contain exactly one \.dist-info directory",
            id="no-dist-info",
        ),
        pytest.param(
            {"native-1.0.dist-info/RECORD": b""},
            "has no native-1.0.dist-info/METADATA",
            id="no-metadata",
        ),
        pytest.param(
            {"native-1.0.dist-info/METADATA": b"Name: native\n"},
            "has no native-1.0.dist-info/RECORD",
            id="no-record",
        ),
    ],
)
def test_embed_refuses_non_wheel(tmp_path: Path, files: dict[str, bytes], message: str) -> None:
    with zipfile.ZipFile(archive := tmp_path / "native-1.0-py3-none-any.whl", "w") as handle:
        for name, content in files.items():
            handle.writestr(name, content)
    with pytest.raises(WheelError, match=message):
        write_sbom(archive, "native.cdx.json", b"{}\n", 1_700_000_000)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no POSIX permission bits")
def test_failed_embed_leaves_wheel_and_no_temporary_file(wheel: Path) -> None:  # pragma: win32 no cover
    original = wheel.read_bytes()
    wheel.parent.chmod(0o555)
    try:
        with pytest.raises(OSError, match="Permission denied"):
            write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    finally:
        wheel.parent.chmod(0o755)
    assert [path.name for path in wheel.parent.iterdir()] == [wheel.name]
    assert wheel.read_bytes() == original


def test_embed_refuses_duplicate_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "native-1.0-py3-none-any.whl", "w") as handle:
        handle.writestr("native-1.0.dist-info/METADATA", b"Name: native\n")
        handle.writestr("native-1.0.dist-info/RECORD", b"")
        with pytest.warns(UserWarning, match="Duplicate name"):
            handle.writestr("native-1.0.dist-info/RECORD", b"")
    with pytest.raises(WheelError, match=r"holds more than one member named native-1\.0\.dist-info/record"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)


def test_embed_refuses_corrupt_archive(tmp_path: Path) -> None:
    (wheel := tmp_path / "native-1.0-py3-none-any.whl").write_bytes(b"not a zip")
    with pytest.raises(WheelError, match="is not a valid zip archive: File is not a zip file"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)


@pytest.mark.parametrize(
    "names",
    [
        pytest.param(("a.py", "A.py"), id="case"),
        pytest.param(("pkg/a.py", "PKG/a.py"), id="directory-case"),
    ],
)
def test_archive_refuses_names_equal_ignoring_case(names: tuple[str, str]) -> None:
    message = f"bundled wheel w-1.0-py3-none-any.whl holds more than one member named {names[0].lower()}, ignoring case"
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(zip_of(*((name, b"") for name in names)), "w-1.0-py3-none-any.whl")


def zip_of(*members: tuple[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_archive_refuses_corrupt_member() -> None:
    data = bytearray(zip_of(("w-1.0.dist-info/METADATA", b"hello" * 1000)))
    data[70:80] = b"\xff" * 10
    with pytest.raises(WheelError, match="w-1.0-py3-none-any.whl is not a valid zip"):
        read_bundled_wheel(bytes(data), "w-1.0-py3-none-any.whl")


def test_member_over_limit() -> None:
    data = zip_of(("w-1.0.dist-info/METADATA", b"A" * (16 * 1024 * 1024 + 1)))
    with pytest.raises(WheelError, match=r"w-1.0.dist-info/METADATA is over the 16777216 byte limit"):
        read_bundled_wheel(data, "w-1.0-py3-none-any.whl")


def test_member_missing() -> None:
    with pytest.raises(WheelError, match="has no w-1.0.dist-info/METADATA"):
        read_bundled_wheel(zip_of(("w-1.0.dist-info/RECORD", b"")), "w-1.0-py3-none-any.whl")


def test_member_with_understated_size_fails_its_crc() -> None:
    # the archive claims 10 bytes for 32 MiB; the core inflates no more than the stated size before the CRC check
    data = bytearray(zip_of(("w-1.0.dist-info/METADATA", b"A" * 32 * 1024 * 1024)))
    data[22:26] = data[(central := data.rfind(b"PK\x01\x02")) + 24 : central + 28] = struct.pack("<I", 10)
    with pytest.raises(WheelError, match="Bad CRC-32 for file 'w-1.0.dist-info/METADATA'"):
        read_bundled_wheel(bytes(data), "w-1.0-py3-none-any.whl")


def test_wheel_with_two_dist_info_directories(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {
            "aaa-0.dist-info/METADATA": b"Name: aaa\nVersion: 0\n",
            "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\n",
        },
        record=False,
    )
    message = r"Wheel doesn't contain exactly one \.dist-info directory .*'aaa-0\.dist-info', 'native-1\.0\.dist-info'"
    with pytest.raises(WheelError, match=message):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 0)
