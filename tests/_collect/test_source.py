from __future__ import annotations

import base64
import dataclasses
import hashlib
import zipfile
from email import message_from_string
from itertools import starmap
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._collect._source import read_bundled_wheel, read_source_tree, wheel_request
from python_sbom._errors import WheelError
from python_sbom._model._inputs import BuildScript, RecordRow, SbomRequest

if TYPE_CHECKING:
    from collections.abc import Mapping

    from conftest import WriteWheel

    from python_sbom._model._inputs import Settings

_INIT: Final[str] = "pip/__init__.py"
_METADATA: Final[str] = "pip-1.0.dist-info/METADATA"
_PIP: Final[dict[str, bytes]] = {_INIT: b"", _METADATA: b"Name: pip\nVersion: 1.0\n"}


# defined before the parametrized cases below, which build their RECORD rows with it at import time
def row(path: str, content: bytes, algorithm: str = "sha256", *, encoded: str = "", size: int | None = None) -> str:
    encoded = encoded or base64.urlsafe_b64encode(hashlib.new(algorithm, content).digest()).rstrip(b"=").decode()
    return f"{path},{algorithm}={encoded},{len(content) if size is None else size}\n"


_METADATA_ROW: Final[str] = row(_METADATA, _PIP[_METADATA])


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
    bundled = read_bundled_wheel(wheel.read_bytes(), "src/pip-1.0-py3-none-any.whl")
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
            "METADATA is over the 16777216 byte limit",
            id="oversized-metadata",
        ),
    ],
)
def test_malformed_bundled_wheel(
    tmp_path: Path, write_wheel: WriteWheel, files: Mapping[str, bytes], message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def test_corrupt_bundled_wheel() -> None:
    with pytest.raises(WheelError, match=r"bundled wheel pip\.whl is not a valid zip archive"):
        read_bundled_wheel(b"not a zip", "pip.whl")


def test_bundled_wheel_with_duplicate_member(tmp_path: Path) -> None:
    # installers extract the first copy, so a RECORD that hashes the second one would hide the installed code
    with zipfile.ZipFile(wheel := tmp_path / "pip-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr(_INIT, b"import os\n")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr(_INIT, b"")
        archive.writestr(_METADATA, _PIP[_METADATA])
        archive.writestr("pip-1.0.dist-info/RECORD", f"{row(_INIT, b'')}{_METADATA_ROW}")
    with pytest.raises(WheelError, match=f"holds more than one member named {_INIT}, ignoring case"):
        read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        pytest.param("sha256", "SHA-256", id="sha256"),
        pytest.param("sha384", "SHA-384", id="sha384"),
        pytest.param("sha512", "SHA-512", id="sha512"),
    ],
)
def test_bundled_wheel_record_algorithm(tmp_path: Path, write_wheel: WriteWheel, algorithm: str, expected: str) -> None:
    record = "".join(row(path, content, algorithm) for path, content in _PIP.items())
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    assert [
        (file.path, file.algorithm, file.digest)
        for file in read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl").files
    ] == [(path, expected, hashlib.new(algorithm, content).hexdigest()) for path, content in _PIP.items()]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        pytest.param(f"{_INIT},sha256=x\n", "RECORD row 1 has 2 columns, not 3", id="columns"),
        pytest.param(f"{_INIT},,0\n", f"RECORD row 1 gives no digest for {_INIT}", id="no-digest"),
        pytest.param(_METADATA_ROW, f"RECORD lacks a digest for {_INIT}", id="member-not-recorded"),
        pytest.param(
            f"{row(_INIT, b'', encoded='A' * 43)}{row(_INIT, b'')}{_METADATA_ROW}",
            f"RECORD lists {_INIT} more than once",
            id="listed-twice",
        ),
        pytest.param(
            f"{row(_INIT, b'')}{row(_INIT, b'', 'sha512', encoded='A' * 86)}{_METADATA_ROW}",
            f"RECORD lists {_INIT} more than once",
            id="listed-twice-by-other-algorithm",
        ),
        pytest.param(
            f"{row(_INIT, b'')}{row('pip/ghost.py', b'', 'md5', size=99)}{_METADATA_ROW}",
            "RECORD lists pip/ghost.py, which the wheel does not hold",
            id="recorded-not-member",
        ),
        pytest.param(
            f"{row(_INIT, b'', size=999999)}{_METADATA_ROW}",
            f"the size in RECORD differs from the size of {_INIT}",
            id="size-mismatch",
        ),
        pytest.param(
            f"{row(_INIT, b'', 'sha512', encoded='A' * 86)}{_METADATA_ROW}",
            f"the digest in RECORD differs from the content of {_INIT}",
            id="digest-mismatch",
        ),
    ],
)
def test_record_disagrees_with_wheel(tmp_path: Path, write_wheel: WriteWheel, record: str, message: str) -> None:
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(WheelError, match=message):
        read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def test_record_signatures_need_no_row(tmp_path: Path, write_wheel: WriteWheel) -> None:
    record = "".join(starmap(row, _PIP.items()))
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode(), "pip-1.0.dist-info/RECORD.jws": b"{}"}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    assert [file.path for file in read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl").files] == list(
        _PIP
    )


def test_vendored_metadata_needs_name_and_version(tmp_path: Path, write_wheel: WriteWheel) -> None:
    files = {**_PIP, "pip/_vendor/rich-13.0.dist-info/METADATA": b"Metadata-Version: 2.1\n"}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files)
    with pytest.raises(WheelError, match=r"pip/_vendor/rich-13\.0\.dist-info/METADATA lacks Name or Version"):
        read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


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
        read_bundled_wheel(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def test_wheel_request(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(tmp_path / "native-1.0-py3-none-any.whl", {"native-1.0.dist-info/METADATA": b"Name: native\n"})
    request = wheel_request(wheel, tmp_path, settings, (PurePosixPath("build.py"),))
    assert (request.root, request.metadata["Name"], request.wheel_name, request.settings, request.build_scripts) == (
        tmp_path,
        "native",
        "native-1.0-py3-none-any.whl",
        settings,
        (PurePosixPath("build.py"),),
    )


def test_wheel_request_needs_a_wheel(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    archive = write_wheel(tmp_path / "native.whl", {"native/__init__.py": b""}, record=False)
    with pytest.raises(WheelError, match=r"has no \.dist-info/METADATA, so it is not a wheel"):
        wheel_request(archive, Path(), settings, ())
