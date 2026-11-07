from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import pytest

from python_sbom import ContentProvider, ProviderContext
from python_sbom._collect._archive import member_reader
from python_sbom._generate._pipeline import build_sbom
from python_sbom._model._identity import project_identity
from python_sbom._model._inputs import BuildFacts, Interpreter, SbomRequest, Settings, SourceTree
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from collections.abc import Mapping

    from python_sbom._model._types import Document


class WriteWheel(Protocol):
    def __call__(
        self, wheel: Path, files: Mapping[str, bytes], *, record: bool = True, compression: int = ...
    ) -> Path: ...


class Install(Protocol):
    def __call__(
        self, site: Path, metadata: str, files: Mapping[str, bytes], *, purelib: bool = True, direct_url: str = ""
    ) -> None: ...


class Git(Protocol):
    def __call__(self, *arguments: str) -> str: ...


class ContextFor(Protocol):
    def __call__(self, root: Path, artifact: Path) -> ProviderContext: ...


class Describe(Protocol):
    def __call__(
        self,
        metadata: str = "",
        *,
        settings: Settings = ...,
        facts: BuildFacts = ...,
        source: SourceTree | None = None,
        content: ContentProvider | None = None,
    ) -> Document: ...


@pytest.fixture
def write_wheel() -> WriteWheel:
    def write(
        wheel: Path, files: Mapping[str, bytes], *, record: bool = True, compression: int = zipfile.ZIP_DEFLATED
    ) -> Path:
        members = dict(files)
        if record:
            dist_info = next(name.split("/")[0] for name in files if name.endswith(".dist-info/METADATA"))
            rows = "".join(f"{name},{record_digest(content)},{len(content)}\n" for name, content in files.items())
            members[f"{dist_info}/RECORD"] = f"{rows}{dist_info}/RECORD,,\n".encode()
        wheel.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in members.items():
                # Unix, the default everywhere but Windows, so the bytes match across operating systems
                (info := zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))).create_system = 3
                archive.writestr(info, content, compression)
        return wheel

    return write


def record_digest(content: bytes) -> str:
    return f"sha256={base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()}"


@pytest.fixture
def install() -> Install:
    def install(
        site: Path, metadata: str, files: Mapping[str, bytes], *, purelib: bool = True, direct_url: str = ""
    ) -> None:
        name, version = (line.split(": ", 1)[1] for line in metadata.splitlines()[:2])
        dist_info = f"{name}-{version}.dist-info"
        members = {
            **files,
            f"{dist_info}/METADATA": metadata.encode(),
            f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nRoot-Is-Purelib: {str(purelib).lower()}\n".encode(),
        }
        if direct_url:
            members[f"{dist_info}/direct_url.json"] = direct_url.encode()
        rows = "".join(f"{path},{record_digest(content)},{len(content)}\n" for path, content in members.items())
        members[f"{dist_info}/RECORD"] = f"{rows}{dist_info}/RECORD,,\n".encode()
        for path, content in members.items():
            (target := site / path).parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    return install


@pytest.fixture
def git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Git:
    # the user's git configuration, such as commit signing, stays out of the test repository
    (config := tmp_path / "gitconfig").write_text("[user]\nname = Test\nemail = test@example.com\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    (checkout := tmp_path / "checkout").mkdir()
    executable = shutil.which("git")
    assert executable is not None

    def run(*arguments: str) -> str:
        return subprocess.run(
            [executable, "-C", str(checkout), *arguments], check=True, capture_output=True, text=True
        ).stdout.strip()

    run("init", "--quiet")
    return run


@pytest.fixture
def facts() -> BuildFacts:
    return BuildFacts(
        epoch=1_700_000_000,
        epoch_from_environment=False,
        revision=None,
        interpreter=Interpreter(name="cpython", version="3.15.0", implementation="CPython"),
        distributions=[],
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(supplier=None, repository=None, default_branch="main", bundled_wheels=(), content_provider=None)


@pytest.fixture
def describe(settings: Settings, facts: BuildFacts) -> Describe:
    def describe(
        metadata: str = "",
        *,
        settings: Settings = settings,
        facts: BuildFacts = facts,
        source: SourceTree | None = None,
        content: ContentProvider | None = None,
    ) -> Document:
        request = SbomRequest(
            root=Path(),
            metadata=parse_metadata(f"Name: Example\nVersion: 1.0\n{metadata}"),
            wheel_name="example-1.0-py3-none-any.whl",
            settings=settings,
            build_scripts=(),
        )
        context = ProviderContext(
            root=Path(),
            settings=settings,
            identity=project_identity(request.metadata, settings),
            read=member_reader(Path("example-1.0-py3-none-any.whl")),
        )
        return build_sbom(
            request,
            source or SourceTree(copyright=None, bundled=[], build_scripts=[]),
            facts,
            content or ContentProvider(),
            context,
        ).document

    return describe


@pytest.fixture
def context_for(settings: Settings) -> ContextFor:
    def context(root: Path, artifact: Path) -> ProviderContext:
        identity = project_identity(parse_metadata("Name: Example\nVersion: 1.0\n"), settings)
        return ProviderContext(root=root, settings=settings, identity=identity, read=member_reader(artifact))

    return context
