from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

from python_sbom import BundledWheelInfo, ContentProvider, ProviderContext
from python_sbom._formats._json import dumps
from python_sbom._generate._embed import build_sbom, embed_sbom
from python_sbom._model._inputs import SbomRequest, SourceTree
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    import pytest
    from conftest import ContextFor, Install, WriteWheel
    from pytest_mock import MockerFixture

    from python_sbom._model._inputs import BuildFacts, Settings

_PINNED: Final[Path] = Path(__file__).parent / "pinned"


def test_bundled_wheel_named_by_its_path_inside_the_wheel(tmp_path: Path, write_wheel: WriteWheel) -> None:
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_text("[tool.python-sbom]\nbundled-wheels = ['src/pkg/wheels/*.whl']\n")
    bundled = write_wheel(
        root / "src" / "pkg" / "wheels" / "pip-1.0-py3-none-any.whl",
        {"pip/__init__.py": b"", "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\nLicense-Expression: MIT\n"},
    )
    wheel = write_wheel(
        tmp_path / "dist" / "pkg-1.0-py3-none-any.whl",
        {
            "pkg/wheels/pip-1.0-py3-none-any.whl": bundled.read_bytes(),
            "pkg/wheels/table.txt": b"3.15\n",
            "pkg-1.0.dist-info/METADATA": b"Name: pkg\nVersion: 1.0\n",
        },
    )
    written = embed_sbom(wheel, root, provider=Table("table.txt"), commit=None, build_env=[str(root)])
    (pip,) = json.loads(zipfile.ZipFile(wheel).read(written))["components"]
    assert (pip["bom-ref"], pip["properties"][:2]) == (
        "bundled:pkg/wheels/pip-1.0-py3-none-any.whl",
        [
            {"name": "pkg:bundled-wheel", "value": "pkg/wheels/pip-1.0-py3-none-any.whl"},
            {"name": "pkg:table", "value": "3.15"},
        ],
    )


class Table(ContentProvider):
    def __init__(self, name: str) -> None:
        self._name = name

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        # the table sits next to the wheel inside the built wheel
        value = context.read(wheel.parent / self._name).decode().strip()
        return BundledWheelInfo(properties=[{"name": f"{context.identity.property_prefix}:table", "value": value}])


def test_identical_bundled_copies_keep_their_own_paths(tmp_path: Path, write_wheel: WriteWheel) -> None:
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_text("[tool.python-sbom]\nbundled-wheels = ['src/*/wheels/*.whl']\n")
    pip = {"pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\nLicense-Expression: MIT\n"}
    for package in ("a", "b"):
        content = write_wheel(root / "src" / package / "wheels" / "pip-1.0-py3-none-any.whl", pip).read_bytes()
    wheel = write_wheel(
        tmp_path / "dist" / "pkg-1.0-py3-none-any.whl",
        {
            "a/wheels/pip-1.0-py3-none-any.whl": content,
            "b/wheels/pip-1.0-py3-none-any.whl": content,
            "pkg-1.0.dist-info/METADATA": b"Name: pkg\nVersion: 1.0\n",
        },
    )
    written = embed_sbom(wheel, root, provider=None, commit=None, build_env=[str(root)])
    assert [component["bom-ref"] for component in json.loads(zipfile.ZipFile(wheel).read(written))["components"]] == [
        "bundled:a/wheels/pip-1.0-py3-none-any.whl",
        "bundled:b/wheels/pip-1.0-py3-none-any.whl",
    ]


def test_embed_output_is_pinned(
    tmp_path: Path, write_wheel: WriteWheel, install: Install, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    # every input fixed, down to the interpreter's version, so the SBOM and the wheel's members must not change by a
    # byte; a change that means to alter them updates the pinned files with it
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    mocker.patch("platform.python_version", autospec=True, return_value="3.14.0")
    metadata = b"""\
Metadata-Version: 2.4
Name: Pkg.Name
Version: 1.0
Summary: a pinned example
Keywords: sbom,pinned
Author: Author Name
Author-email: Author <author@example.com>, plain@example.com
Maintainer-email: not-an-email
License-Expression: MIT OR Apache-2.0
License-File: LICENSE
Classifier: License :: OSI Approved :: MIT License
Classifier: Programming Language :: Python :: 3
Project-URL: Source, https://github.com/example/pkg
Project-URL: Source, https://gitlab.com/example/pkg
Project-URL: Documentation, https://pkg.readthedocs.io
Project-URL: Bug Tracker, https://github.com/example/pkg/issues
Requires-Dist: alpha>=1
Requires-Dist: beta; extra == "cli"
Requires-Dist: gamma; python_version < "3"
Requires-Dist: delta; extra in "a,b"
Provides-Extra: cli
"""
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_bytes(
        b"[tool.python-sbom]\nsupplier = { name = 'Example Org', url = ['https://example.org'] }\n"
        b"bundled-wheels = ['src/pkg/wheels/*.whl']\n"
    )
    pip = {
        "pip/__init__.py": b"",
        "pip/_vendor/vendor.txt": b"urllib3==1.26.4\nidna==3.7\n",
        "pip-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: pip\nVersion: 1.0\nLicense-Expression: MIT\n",
    }
    # stored, as deflate output differs between zlib builds and the SBOM records the bundled wheel's hash
    bundled = write_wheel(root / "src" / "pkg" / "wheels" / "pip-1.0-py3-none-any.whl", pip, compression=0)
    site = tmp_path / "site-packages"
    install(site, "Name: alpha\nVersion: 1.0\nRequires-Dist: beta\n", {"alpha.py": b"", "../../bin/alpha": b""})
    install(site, "Name: beta\nVersion: 2.0\n", {"beta.so": b"\x7fELF"}, purelib=False)
    install(site, "Name: gamma\nVersion: 3.0\n", {}, direct_url='{"url": "file:///c", "dir_info": {"editable": true}}')
    wheel = write_wheel(
        tmp_path / "dist" / "pkg_name-1.0-py3-none-any.whl",
        {
            "pkg_name/__init__.py": b"x = 1\n",
            "pkg_name/wheels/pip-1.0-py3-none-any.whl": bundled.read_bytes(),
            "pkg_name-1.0.dist-info/METADATA": metadata,
            "pkg_name-1.0.dist-info/licenses/LICENSE": b"MIT terms\n",
            "pkg_name-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        },
        compression=0,
    )
    written = embed_sbom(wheel, root, provider=None, commit="a" * 40, build_env=[str(site)])
    with zipfile.ZipFile(wheel) as archive:
        sbom = archive.read(written)
        members = [
            [info.filename, list(info.date_time), info.compress_type, info.external_attr, _sha256(archive.read(info))]
            for info in archive.infolist()
        ]
    assert sbom == (_PINNED / "embed.cdx.json").read_bytes()
    assert members == json.loads((_PINNED / "embed-members.json").read_bytes())


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def test_sbom_file_name_and_content(settings: Settings, facts: BuildFacts, context_for: ContextFor) -> None:
    request = SbomRequest(
        root=Path(),
        metadata=parse_metadata("Name: My.Project\nVersion: 1.0\n"),
        wheel_name="my_project-1.0-py3-none-any.whl",
        settings=settings,
        build_scripts=(),
    )
    context = context_for(Path(), Path())
    sbom = build_sbom(
        request, SourceTree(copyright=None, bundled=[], build_scripts=[]), facts, ContentProvider(), context
    )
    assert (sbom.file_name, sbom.content) == ("my-project.cdx.json", dumps(sbom.document))
