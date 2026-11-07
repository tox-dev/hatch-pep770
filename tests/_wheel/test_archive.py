from __future__ import annotations

import stat
import struct
import sys
import tracemalloc
import zipfile
from contextlib import ExitStack
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._errors import WheelError
from python_sbom._wheel._archive import open_archive, read_member, write_sbom

if TYPE_CHECKING:
    from collections.abc import Iterator

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
def test_open_archive_refuses_names_equal_ignoring_case(names: tuple[str, str]) -> None:
    message = f"w holds more than one member named {names[0].lower()}, ignoring case"
    with pytest.raises(WheelError, match=message), ExitStack() as stack:
        stack.enter_context(open_archive(zip_of(*((name, b"") for name in names)), "w"))


def zip_of(*members: tuple[str, bytes]) -> BytesIO:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return buffer


def test_open_archive_refuses_corrupt_member() -> None:
    data = bytearray(zip_of(("a", b"hello" * 1000)).getvalue())
    data[40:50] = b"\xff" * 10
    with pytest.raises(WheelError, match="w is not a valid zip"), open_archive(BytesIO(bytes(data)), "w") as archive:
        archive.read("a")


def test_read_member() -> None:
    with open_archive(zip_of(("a", b"12345")), "w") as archive:
        assert read_member(archive, "a", "w", limit=5) == b"12345"


def test_read_member_over_limit() -> None:
    with open_archive(zip_of(("a", b"12345")), "w") as archive, pytest.raises(WheelError, match="w: a is over the 4"):
        read_member(archive, "a", "w", limit=4)


def test_read_member_missing() -> None:
    with open_archive(zip_of(("a", b"")), "w") as archive, pytest.raises(WheelError, match="w has no b"):
        read_member(archive, "b", "w")


@pytest.mark.usefixtures("traced")
def test_read_member_refuses_understated_size() -> None:
    # the archive claims 10 bytes for 32 MiB; reading the member whole would decompress all of it before the CRC check
    data = bytearray(zip_of(("a", b"A" * 32 * 1024 * 1024)).getvalue())
    data[22:26] = data[(central := data.rfind(b"PK\x01\x02")) + 24 : central + 28] = struct.pack("<I", 10)
    tracemalloc.reset_peak()
    with pytest.raises(WheelError, match="Bad CRC-32 for file 'a'"), open_archive(BytesIO(bytes(data)), "w") as archive:
        read_member(archive, "a", "w")
    assert tracemalloc.get_traced_memory()[1] < 4 * 1024 * 1024


@pytest.fixture
def traced() -> Iterator[None]:
    tracemalloc.start()
    yield
    tracemalloc.stop()


def test_wheel_with_two_dist_info_directories(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(
        tmp_path / "native-1.0-py3-none-any.whl",
        {
            "aaa-0.dist-info/METADATA": b"Name: aaa\nVersion: 0\n",
            "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\n",
        },
        record=False,
    )
    with pytest.raises(WheelError, match=r"holds 2 \.dist-info directories, aaa-0\.dist-info, native-1\.0\.dist-info"):
        write_sbom(wheel, "native.cdx.json", b"{}\n", 0)
