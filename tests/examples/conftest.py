from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol

import pytest

if TYPE_CHECKING:
    from python_sbom._model._types import Document  # simplint: ignore[private-import-path]  # test uses internal model

_EXAMPLES: Final[Path] = Path(__file__).parents[2] / "docs" / "examples"
# a wheel's interpreter, ABI and platform tags depend on where the example runs, while the docs show one platform's
_TAGS: Final[re.Pattern[str]] = re.compile(r"-[^-\s/]+-[^-\s/]+-[^-\s/]+\.whl\b")
_PROMPT: Final[re.Pattern[str]] = re.compile(r"^\$ ", re.MULTILINE)
# a frontend's isolated environment would install python-sbom from PyPI; the environment the test runs in holds the
# checkout's
_ADDED: Final[MappingProxyType[tuple[str, ...], list[str]]] = MappingProxyType({
    ("python", "-m", "build"): ["--no-isolation", "--skip-dependency-check"]
})


class ReadSbom(Protocol):
    def __call__(self, wheel: Path) -> Document: ...


@pytest.fixture(scope="module")
def played(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Played:
    example, session = request.param
    directory = tmp_path_factory.mktemp(example) / "greet"
    shutil.copytree(_EXAMPLES / example, directory)
    expected: Final[list[tuple[str, list[str]]]] = []
    output: Final[list[tuple[str, list[str]]]] = []
    for block in _PROMPT.split((_EXAMPLES / example / session).read_text(encoding="utf-8"))[1:]:
        command, *lines = block.splitlines()
        expected.append((command, [_TAGS.sub("-TAGS.whl", line) for line in lines]))
        output.append((command, [_TAGS.sub("-TAGS.whl", line) for line in _run(command, directory)]))
    return Played(directory=directory, expected=expected, output=output)


def _run(command: str, directory: Path) -> list[str]:
    name, *typed = shlex.split(command)
    # the shell expands the globs a reader types
    arguments: Final[list[str]] = []
    for argument in typed:
        arguments.extend(
            sorted(path.relative_to(directory).as_posix() for path in directory.glob(argument)) or [argument]
        )
    arguments.extend(_ADDED.get((name, *arguments[:2]), []))
    executable = sys.executable if name == "python" else shutil.which(name, path=sysconfig.get_path("scripts"))
    assert executable is not None, f"{name} is not installed next to {sys.executable}"
    result = subprocess.run([executable, *arguments], cwd=directory, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"{command} failed:\n{result.stdout}{result.stderr}"
    # the docs show what python-sbom prints and leave out what the build tools around it print
    return result.stdout.splitlines() if name == "python-sbom" else []


@dataclass(frozen=True, slots=True, kw_only=True)
class Played:
    # an example project of the docs, copied and taken through one of its documented sessions: each command with the
    # lines the docs show under it, and with the lines it printed
    directory: Path
    expected: list[tuple[str, list[str]]]
    output: list[tuple[str, list[str]]]


@pytest.fixture
def read_sbom() -> ReadSbom:
    def read(wheel: Path) -> Document:
        return json.loads(zipfile.ZipFile(wheel).read("greet-1.0.dist-info/sboms/greet.cdx.json"))

    return read
