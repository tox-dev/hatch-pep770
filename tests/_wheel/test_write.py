from __future__ import annotations

import stat
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import SbomError
from python_sbom._wheel._write import append_member, write_sbom

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
    with pytest.raises(SbomError, match=message):
        write_sbom(archive, "native.cdx.json", b"{}\n", 1_700_000_000)


def test_failed_embed_leaves_wheel_and_no_temporary_file(wheel: Path, mocker: MockerFixture) -> None:
    original = wheel.read_bytes()
    mocker.patch.object(Path, "replace", autospec=True, side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert [path.name for path in wheel.parent.iterdir()] == [wheel.name]
    assert wheel.read_bytes() == original


def test_embed_refuses_duplicate_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "native-1.0-py3-none-any.whl", "w") as handle:
        handle.writestr("native-1.0.dist-info/METADATA", b"Name: native\n")
        handle.writestr("native-1.0.dist-info/RECORD", b"")
        with pytest.warns(UserWarning, match="Duplicate name"):
            handle.writestr("native-1.0.dist-info/RECORD", b"")
    with pytest.raises(SbomError, match=r"holds more than one member named native-1\.0\.dist-info/record"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)


def test_embed_refuses_corrupt_archive(tmp_path: Path) -> None:
    (wheel := tmp_path / "native-1.0-py3-none-any.whl").write_bytes(b"not a zip")
    with pytest.raises(SbomError, match="is not a valid zip archive: File is not a zip file"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)


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
    with pytest.raises(SbomError, match=message):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 0)


def test_embed_ends_an_unterminated_last_row(tmp_path: Path, write_wheel: WriteWheel) -> None:
    # no row for RECORD itself, and no line end after the last row, so the SBOM's row goes after it on a line of its own
    record = b"native-1.0.dist-info/METADATA,,"
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {"native-1.0.dist-info/METADATA": b"Name: native\n", "native-1.0.dist-info/RECORD": record},
        record=False,
    )
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD").decode().splitlines() == [
        "native-1.0.dist-info/METADATA,,",
        _SBOM_ROW,
    ]


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        pytest.param(
            b'native-1.0.dist-info/METADATA,,\n"native-1.0.dist-info/sboms/native.cdx.json",sha256=stale,1\n'
            b"native-1.0.dist-info/RECORD,,\n",
            f"native-1.0.dist-info/METADATA,,\n{_SBOM_ROW}\nnative-1.0.dist-info/RECORD,,\n".encode(),
            id="quoted-sbom-row",
        ),
        pytest.param(
            b'native-1.0.dist-info/METADATA,,\n"native-1.0.dist-info/RECORD",,\n',
            f'native-1.0.dist-info/METADATA,,\n{_SBOM_ROW}\n"native-1.0.dist-info/RECORD",,\n'.encode(),
            id="quoted-record-row",
        ),
        pytest.param(
            b"native-1.0.dist-info/METADATA,,\r\n"
            b'"native-1.0.dist-info/sboms/native.cdx.json",sha256=stale,1\r\n'
            b"native-1.0.dist-info/RECORD,,\r\n",
            f"native-1.0.dist-info/METADATA,,\r\n{_SBOM_ROW}\r\nnative-1.0.dist-info/RECORD,,\r\n".encode(),
            id="crlf",
        ),
        pytest.param(
            b"native-1.0.dist-info/METADATA,,\nnative-1.0.dist-info/RECORD,,",
            f"native-1.0.dist-info/METADATA,,\n{_SBOM_ROW}\nnative-1.0.dist-info/RECORD,,\n".encode(),
            id="no-final-newline",
        ),
    ],
)
def test_embed_rewrites_record_by_parsed_path(
    tmp_path: Path, write_wheel: WriteWheel, record: bytes, expected: bytes
) -> None:
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {"native-1.0.dist-info/METADATA": b"Name: native\n", "native-1.0.dist-info/RECORD": record},
        record=False,
    )
    write_sbom(wheel, "native.cdx.json", b"{}\n", 1_700_000_000)
    assert zipfile.ZipFile(wheel).read("native-1.0.dist-info/RECORD") == expected


def test_append_member_deflates_at_level_nine(tmp_path: Path) -> None:
    # the archive stores its members, as virtualenv's zipapp does, yet the SBOM goes in deflated, and the members keep
    # their bytes
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w", zipfile.ZIP_STORED) as handle:
        handle.writestr("__main__.py", b"import app\n" * 100)
    before = _stored(archive, "__main__.py")
    content = b'{"components": []}\n' * 100
    append_member(archive, "app.pyz.cdx.json", content, 1_700_000_000)
    entry = zipfile.ZipFile(archive).getinfo("app.pyz.cdx.json")
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    assert (
        entry.compress_type,
        entry.create_system,
        entry.date_time,
        entry.external_attr,
        _stored(archive, "app.pyz.cdx.json"),
        _stored(archive, "__main__.py"),
    ) == (
        zipfile.ZIP_DEFLATED,
        3,
        (2023, 11, 14, 22, 13, 20),
        (stat.S_IFREG | 0o644) << 16,
        compressor.compress(content) + compressor.flush(),
        before,
    )


def test_append_member_refuses_a_second_copy(tmp_path: Path) -> None:
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("app.pyz.cdx.json", b"{}")
    with pytest.raises(SbomError, match=r"app\.pyz already holds app\.pyz\.cdx\.json"):
        append_member(archive, "app.pyz.cdx.json", b"{}\n", 1_700_000_000)
