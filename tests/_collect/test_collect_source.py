from __future__ import annotations

import dataclasses
import hashlib
from email import message_from_string
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest
from conftest import record_digest

from python_sbom import BuildScript, RecordRow, SbomRequest, WheelError, read_bundled_wheel, read_source_tree

if TYPE_CHECKING:
    from collections.abc import Mapping

    from conftest import WriteWheel

    from python_sbom import Settings

_PIP: Final[dict[str, bytes]] = {
    "pip/__init__.py": b"",
    "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n",
}


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        pytest.param({}, None, id="no-license-file"),
        pytest.param({"LICENSE": "MIT terms\n"}, None, id="no-copyright-line"),
        pytest.param(
            {"LICENSE": "MIT\n\nCopyright (c) 2026 Example\nCopyright (c) 2025 Other\n"},
            "Copyright (c) 2026 Example",
            id="first-copyright-line",
        ),
    ],
)
def test_copyright(tmp_path: Path, settings: Settings, files: Mapping[str, str], expected: str | None) -> None:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    source = read_source_tree(request(tmp_path, settings, "License-File: LICENSE\nLicense-File: NOTICE\n"))
    assert source.copyright == expected


def request(root: Path, settings: Settings, metadata: str = "", scripts: tuple[PurePosixPath, ...] = ()) -> SbomRequest:
    return SbomRequest(
        root=root,
        metadata=message_from_string(f"Name: example\nVersion: 1.0\n{metadata}"),
        wheel_name="example-1.0-py3-none-any.whl",
        settings=settings,
        build_scripts=scripts,
    )


def test_bundled_wheels_sorted_once(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    for directory in ("b", "a"):
        write_wheel(tmp_path / "src" / directory / "pip-1.0-py3-none-any.whl", _PIP)
    settings = dataclasses.replace(settings, bundled_wheels=("src/*/*.whl", "src/a/*.whl"))
    paths = [wheel.path for wheel in read_source_tree(request(tmp_path, settings)).bundled]
    assert paths == ["src/a/pip-1.0-py3-none-any.whl", "src/b/pip-1.0-py3-none-any.whl"]


def test_build_scripts_hashed(tmp_path: Path, settings: Settings) -> None:
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath("hatch_build.py")
    source = read_source_tree(request(tmp_path, settings, scripts=(script,)))
    assert source.build_scripts == [BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())]


def test_build_script_outside_project(tmp_path: Path, settings: Settings) -> None:
    # a custom hook path may be absolute, which on Windows carries a drive the join with the root must keep
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath((tmp_path / "hatch_build.py").as_posix())
    source = read_source_tree(request(tmp_path / "project", settings, scripts=(script,)))
    assert source.build_scripts == [BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())]


def test_bundled_wheel(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(
        tmp_path / "src" / "pip-1.0-py3-none-any.whl",
        {
            **_PIP,
            "pip/_vendor/vendor.txt": b"# pinned\n\nurllib3==1.26.4  # http\n",
            "pip/_vendor/rich-13.0.dist-info/METADATA": b"Name: rich\nVersion: 13.0\n",
        },
    )
    bundled = read_bundled_wheel(tmp_path, wheel)
    assert (bundled.path, bundled.sha256, bundled.metadata_name, bundled.metadata["Name"], bundled.files[0]) == (
        "src/pip-1.0-py3-none-any.whl",
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "pip-1.0.dist-info/METADATA",
        "pip",
        RecordRow(path="pip/__init__.py", algorithm="SHA-256", digest=hashlib.sha256(b"").hexdigest(), size="0"),
    )
    assert [(source, str(metadata)) for source, metadata in bundled.vendored] == [
        ("pip/_vendor/vendor.txt", "Name: urllib3\nVersion: 1.26.4\n\n"),
        ("pip/_vendor/rich-13.0.dist-info/METADATA", "Name: rich\nVersion: 13.0\n\n"),
    ]


_EMPTY: Final[str] = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
_METADATA: Final[str] = f"pip-1.0.dist-info/METADATA,sha256={_EMPTY},0\n"


@pytest.mark.parametrize(
    ("files", "message"),
    [
        pytest.param({"pip/__init__.py": b""}, "has no .dist-info/METADATA", id="no-metadata"),
        pytest.param({"pip-1.0.dist-info/METADATA": b"Name: pip\n"}, "METADATA lacks Name or Version", id="no-version"),
        pytest.param(
            {"pip-1.0.dist-info/METADATA": _PIP["pip-1.0.dist-info/METADATA"]},
            "has no pip-1.0.dist-info/RECORD",
            id="no-record",
        ),
        pytest.param(
            {"pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n" + b" " * 16 * 1024 * 1024},
            "METADATA is 16777239 bytes, over the 16777216 byte limit",
            id="oversized-metadata",
        ),
    ],
)
def test_malformed_bundled_wheel(
    tmp_path: Path, write_wheel: WriteWheel, files: Mapping[str, bytes], message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(tmp_path, wheel)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        pytest.param("pip/__init__.py,sha256=x\n", "RECORD row 1 has 2 columns, not 3", id="columns"),
        pytest.param("pip/__init__.py,blake2b=x,0\n", "RECORD row 1: unknown hash algorithm 'blake2b'", id="algorithm"),
        pytest.param("pip/__init__.py,sha256=abcde,0\n", "digest 'abcde' is not urlsafe base64", id="base64"),
        pytest.param(_METADATA, "RECORD lacks a SHA-256 for pip/__init__.py", id="member-not-recorded"),
        pytest.param(
            f"{_METADATA}pip/__init__.py,sha256={_EMPTY},0\npip/gone.py,sha256={_EMPTY},0\n",
            "RECORD lists pip/gone.py, which the wheel does not hold",
            id="recorded-not-member",
        ),
        pytest.param(
            f"pip/__init__.py,sha256={_EMPTY},0\npip-1.0.dist-info/METADATA,sha256={_EMPTY},0\n",
            "the SHA-256 in RECORD differs from the content of pip-1.0.dist-info/METADATA",
            id="digest-mismatch",
        ),
    ],
)
def test_record_disagrees_with_wheel(tmp_path: Path, write_wheel: WriteWheel, record: str, message: str) -> None:
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(tmp_path, wheel)


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        pytest.param(b"urllib3 ==\n", "does not parse: urllib3 ==", id="unparsable"),
        pytest.param(b"urllib3>=1\n", "pins no one exact version: urllib3>=1", id="range"),
        pytest.param(b"urllib3==1.*\n", "pins no one exact version: urllib3==1.*", id="wildcard"),
        pytest.param(b"urllib3==1,!=1.1\n", "pins no one exact version: urllib3==1,!=1.1", id="two-specifiers"),
    ],
)
def test_vendor_manifest_needs_exact_pins(
    tmp_path: Path, write_wheel: WriteWheel, manifest: bytes, message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", {**_PIP, "pip/_vendor/vendor.txt": manifest})
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(tmp_path, wheel)


def test_record_blank_lines_are_skipped(tmp_path: Path, write_wheel: WriteWheel) -> None:
    metadata = _PIP["pip-1.0.dist-info/METADATA"]
    record = (
        f"pip/__init__.py,sha256={_EMPTY},0\n\n"
        f"pip-1.0.dist-info/METADATA,{record_digest(metadata)},{len(metadata)}\n"
        "pip-1.0.dist-info/RECORD,,\n"
    )
    wheel = write_wheel(tmp_path / "pip.whl", {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}, record=False)
    assert [row.path for row in read_bundled_wheel(tmp_path, wheel).files] == [
        "pip/__init__.py",
        "pip-1.0.dist-info/METADATA",
    ]
