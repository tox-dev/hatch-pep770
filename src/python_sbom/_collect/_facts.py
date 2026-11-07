from __future__ import annotations

import os
import platform
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # runs git to read the source revision
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import Parser
from importlib.metadata import distributions
from typing import TYPE_CHECKING, Final, Protocol

from packaging.requirements import Requirement

from python_sbom._errors import SourceRevisionError
from python_sbom._model._components import component_from_metadata, file_component, purl

if TYPE_CHECKING:
    from importlib.metadata import Distribution
    from pathlib import Path

    from python_sbom._model._types import Component, Dependency


class RevisionReader(Protocol):
    """Reads the source revision a build comes from."""

    def __call__(self, root: Path, /) -> str | None:
        """
        Read the revision of a source tree.

        :param root: the project directory
        :returns: the revision, or ``None`` when the directory is not under version control
        :raises SourceRevisionError: when it is, but the revision cannot be read

        """


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildFacts:
    """
    What the SBOM records about the build itself, gathered once from the environment that runs it.

    :param epoch: the build time as a Unix timestamp, from ``SOURCE_DATE_EPOCH``
    :param commit: the source revision of a git checkout, or ``None`` outside one
    :param tools: the interpreter and every distribution of the build environment, interpreter first
    :param tool_dependencies: the dependency graph between those distributions

    """

    epoch: int
    commit: str | None
    tools: list[Component]
    tool_dependencies: list[Dependency]

    @classmethod
    def collect(cls, root: Path, revision: RevisionReader) -> BuildFacts:
        """
        Read the build time, the source revision and the build environment.

        Nothing about the machine goes in: the same source, toolchain and ``SOURCE_DATE_EPOCH`` give the same facts
        on any operating system. A pure-Python distribution lists its files with their hashes; a platform one does
        not, because its files differ per machine.

        :param root: the project directory
        :param revision: reads the source revision of ``root``, such as :func:`git_revision`
        :returns: the facts

        """
        tools, tool_dependencies = _build_tools()
        # hatchling's default when the variable is unset, so a hook build and an embed run agree
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1580601600"))
        return cls(epoch=epoch, commit=revision(root), tools=tools, tool_dependencies=tool_dependencies)

    @property
    def timestamp(self) -> str:
        """The build time in ISO 8601."""
        return datetime.fromtimestamp(self.epoch, tz=UTC).isoformat()


def _build_tools() -> tuple[list[Component], list[Dependency]]:
    # nothing about the machine goes in, so the same toolchain yields the same record on any operating system
    interpreter = f"pkg:generic/{sys.implementation.name}@{platform.python_version()}"
    tools: Final[list[Component]] = [
        {
            "type": "platform",
            "bom-ref": f"tool:{interpreter}",
            "name": sys.implementation.name,
            "version": platform.python_version(),
            "purl": interpreter,
            "properties": [{"name": "python:implementation", "value": platform.python_implementation()}],
        },
    ]
    # bom-refs are prefixed because the same distribution can be both a build tool and a component of the artifact
    installed = {purl(distribution.metadata["Name"]): distribution for distribution in distributions()}
    tool_dependencies: Final[list[Dependency]] = []
    for distribution in (installed[key] for key in sorted(installed)):
        component = component_from_metadata(distribution.metadata, "library")
        component["bom-ref"] = f"tool:{component['bom-ref']}"
        if Parser().parsestr(distribution.read_text("WHEEL") or "")["Root-Is-Purelib"] == "true":
            component["components"] = [
                file_component(
                    component["bom-ref"], file.as_posix(), f"{file.hash.mode}={file.hash.value}", str(file.size)
                )
                for file in distribution.files or []
                # console-script launchers live outside site-packages and embed the environment's interpreter path in
                # their shebang, so their hash differs on every build; the installer metadata names the frontend that
                # set up the environment rather than the distribution
                if file.hash is not None
                and not file.as_posix().startswith("../")
                and not (
                    file.parent.suffix == ".dist-info" and file.name in {"INSTALLER", "REQUESTED", "direct_url.json"}
                )
            ]
        tools.append(component)
        tool_dependencies.append({"ref": component["bom-ref"], "dependsOn": _depends_on(distribution, installed)})
    return tools, tool_dependencies


def _depends_on(distribution: Distribution, installed: dict[str, Distribution]) -> list[str]:
    refs = set()
    for requirement in map(Requirement, distribution.requires or []):
        if (requirement.marker is None or requirement.marker.evaluate()) and (
            dependency := installed.get(purl(requirement.name))
        ):
            refs.add(f"tool:{purl(dependency.metadata['Name'], dependency.version)}")
    return sorted(refs)


def git_revision(root: Path, /) -> str | None:
    """
    Read the commit of a git checkout.

    :param root: the project directory
    :returns: the commit, or ``None`` when ``root`` holds no ``.git``, as in a build from an sdist, or git is missing
    :raises SourceRevisionError: when git cannot read the commit, such as in a checkout it considers unsafe

    """
    if not (root / ".git").exists() or (git := shutil.which("git")) is None:
        return None
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed arguments
            [git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, cwd=root
        )
    except subprocess.CalledProcessError as error:
        msg = f"git rev-parse HEAD failed in {root}: {error.stderr.strip()}"
        raise SourceRevisionError(msg) from error
    return result.stdout.strip()


__all__ = [
    "BuildFacts",
    "RevisionReader",
    "git_revision",
]
