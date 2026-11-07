from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] # runs git to read the source revision
import sys
import time
from email.parser import Parser
from importlib.metadata import distributions
from typing import TYPE_CHECKING, Final, Protocol

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from python_sbom._errors import SettingsError, SourceRevisionError
from python_sbom._model._inputs import BuildFacts, InstalledDistribution, Interpreter, RecordRow, Revision
from python_sbom._wheel._record import decode_digest

if TYPE_CHECKING:
    from collections.abc import Sequence
    from importlib.metadata import Distribution
    from pathlib import Path


class RevisionReader(Protocol):
    """Reads the source revision of a project directory."""

    def __call__(self, root: Path, /) -> Revision | None:
        """
        Read the revision.

        :param root: the project directory
        :returns: the revision, or ``None`` when it is unknown
        :raises SourceRevisionError: when version control holds the directory but cannot read its revision

        """


def collect_facts(
    root: Path, revision: RevisionReader, path: Sequence[str] | None, default_epoch: int | None
) -> BuildFacts:
    """
    Gather what the environment says about a build.

    Nothing about the machine goes in: the same toolchain, revision and build time give the same facts on any
    operating system.

    :param root: the project directory
    :param revision: reads the source revision, such as :func:`default_revision`
    :param path: the directories to find the build environment's distributions in, or ``None`` for :data:`sys.path`
    :param default_epoch: the build time when ``SOURCE_DATE_EPOCH`` is unset, such as the fixed time of a reproducible
        hatchling build, or ``None`` for the current time
    :returns: the facts
    :raises SettingsError: when ``SOURCE_DATE_EPOCH`` is not an integer

    """
    if from_environment := bool(raw := os.environ.get("SOURCE_DATE_EPOCH", "")):
        try:
            epoch = int(raw)
        except ValueError as error:
            msg = f"SOURCE_DATE_EPOCH must be a Unix timestamp, got {raw!r}"
            raise SettingsError(msg) from error
    else:
        epoch = int(time.time()) if default_epoch is None else default_epoch
    return BuildFacts(
        epoch=epoch,
        epoch_from_environment=from_environment,
        revision=revision(root),
        interpreter=Interpreter(
            name=sys.implementation.name,
            version=platform.python_version(),
            implementation=platform.python_implementation(),
        ),
        distributions=_installed(path),
    )


def _installed(path: Sequence[str] | None) -> list[InstalledDistribution]:
    found: Final[dict[str, Distribution]] = {}
    for distribution in distributions(path=list(path)) if path is not None else distributions():
        # the first on the path is the one imports load, so a shadowed copy further down is left out
        found.setdefault(canonicalize_name(distribution.metadata["Name"]), distribution)
    return [
        InstalledDistribution(
            metadata=Parser().parsestr(distribution.read_text("METADATA") or ""),
            files=_recorded_files(distribution),
            depends_on=sorted({
                name
                for requirement in map(Requirement, distribution.requires or [])
                if (name := canonicalize_name(requirement.name)) in found
                and (requirement.marker is None or requirement.marker.evaluate())
            }),
        )
        for distribution in found.values()
    ]


def _recorded_files(distribution: Distribution) -> list[RecordRow]:
    # a platform wheel's files are built for this machine's OS and architecture, and an editable install's point at a
    # checkout, so listing either would tie the document to one machine
    if Parser().parsestr(distribution.read_text("WHEEL") or "")["Root-Is-Purelib"] != "true" or (
        json.loads(distribution.read_text("direct_url.json") or "{}").get("dir_info", {}).get("editable")
    ):
        return []
    rows: Final[list[RecordRow]] = []
    for file in distribution.files or []:
        if file.hash is None or not _describes_distribution(file.as_posix(), file.parent.suffix, file.name):
            continue
        algorithm, digest = decode_digest(f"{file.hash.mode}={file.hash.value}", file.as_posix())
        rows.append(RecordRow(path=file.as_posix(), algorithm=algorithm, digest=digest, size=str(file.size)))
    return rows


def _describes_distribution(path: str, parent_suffix: str, name: str) -> bool:
    # console-script launchers live outside site-packages and embed the environment's interpreter path; the installer
    # metadata names the frontend; uv's cache files hold paths and times; none of them says anything about the package
    return not (
        path.startswith("../")
        or (parent_suffix == ".dist-info" and name in {"INSTALLER", "REQUESTED", "direct_url.json"})
        or re.fullmatch(r"uv_.*\.json", name)
    )


def default_revision(root: Path, /) -> Revision | None:
    """
    Read the source revision from the first source that knows it.

    The sources, in order: the ``PYTHON_SBOM_COMMIT`` environment variable, for builds from an sdist; git, for a
    checkout or a directory inside one; and the ``node`` of an expanded ``.git_archival.txt``, for a ``git archive``.

    :param root: the project directory
    :returns: the revision, or ``None`` when no source knows it
    :raises SourceRevisionError: when a git checkout holds the directory but git cannot read its revision

    """
    if commit := os.environ.get("PYTHON_SBOM_COMMIT"):
        return Revision(commit=commit, dirty=False)
    if (found := git_revision(root)) is not None:
        return found
    archival = root / ".git_archival.txt"
    if archival.is_file() and (
        match := re.search(r"^node: ([0-9a-f]{40,64})$", archival.read_text(encoding="utf-8"), re.MULTILINE)
    ):
        return Revision(commit=match[1], dirty=False)
    return None


def git_revision(root: Path, /) -> Revision | None:
    """
    Read the commit of the git checkout that holds a directory.

    :param root: the project directory, or any directory inside a checkout
    :returns: the commit and whether tracked files changed, or ``None`` outside a checkout, without git, or before the
        first commit
    :raises SourceRevisionError: when git cannot read the checkout, such as one it considers unsafe

    """
    resolved = root.resolve()
    if (git := shutil.which("git")) is None or not any(
        (directory / ".git").exists() for directory in (resolved, *resolved.parents)
    ):
        return None
    head = _git(git, root, "rev-parse", "--verify", "--quiet", "HEAD")
    if head.returncode == 1:  # a checkout before its first commit
        return None
    if head.returncode:
        msg = f"git rev-parse HEAD failed in {root}: {head.stderr.strip()}"
        raise SourceRevisionError(msg)
    status = _git(git, root, "status", "--porcelain", "--untracked-files=no")
    return Revision(commit=head.stdout.strip(), dirty=bool(status.stdout.strip()))


def _git(git: str, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] # git from PATH with fixed arguments
        [git, "-C", str(root), *arguments], check=False, capture_output=True, text=True
    )


__all__ = [
    "RevisionReader",
    "collect_facts",
    "default_revision",
    "git_revision",
]
