from __future__ import annotations

import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] # runs git to read the source revision
import warnings
from typing import TYPE_CHECKING, Final, Protocol

from python_sbom._errors import SettingsError
from python_sbom._model._inputs import Revision

if TYPE_CHECKING:
    from pathlib import Path

#: the file an sdist carries its source revision in, as ``node: <commit>``, for the wheel built from it
REVISION_FILE: Final[str] = ".python-sbom-revision"
_COMMIT: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class RevisionReader(Protocol):
    def __call__(self, root: Path, /) -> Revision | None: ...


def revision_reader(commit: str | None) -> RevisionReader:
    # a commit given on the command line stands for the checkout, so git and the files go unread
    if commit is None:
        return default_revision
    revision = _commit_revision(commit, "--commit")
    return lambda _root: revision


def default_revision(root: Path, /) -> Revision | None:
    # the variable exists for builds from an sdist, so it wins over whatever checkout the sdist was unpacked into
    if commit := os.environ.get("PYTHON_SBOM_COMMIT"):
        return _commit_revision(commit, "PYTHON_SBOM_COMMIT")
    if (found := _git_revision(root)) is not None:
        return found
    # the sdist build wrote it from the revision it resolved, so it is at least as exact as an archival file
    if (recorded := root / REVISION_FILE).is_file():
        return _commit_revision(recorded.read_text(encoding="utf-8").strip().removeprefix("node: "), REVISION_FILE)
    archival = root / ".git_archival.txt"
    if archival.is_file() and (
        match := re.search(rf"^node: ({_COMMIT.pattern})$", archival.read_text(encoding="utf-8"), re.MULTILINE)
    ):
        return Revision(commit=match[1], dirty=False)
    return None


def _git_revision(root: Path, /) -> Revision | None:
    resolved = root.resolve()
    if (git := shutil.which("git")) is None or not any(
        (directory / ".git").exists() for directory in (resolved, *resolved.parents)
    ):
        return None
    try:
        # a project unpacked into another checkout, such as an sdist under its build directory, is not its source
        _git(git, root, "ls-files", "--error-unmatch", "--", "pyproject.toml")
        commit = _git(git, root, "rev-parse", "--verify", "--quiet", "HEAD")
        # untracked files count, since the build packages every file .gitignore lets through
        changes = _git(git, root, "status", "--porcelain", "--", ".")
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:  # 1: the project is untracked, or the checkout has no commit yet
            warnings.warn(f"git cannot read the source revision in {root}: {error.stderr.strip()}", stacklevel=2)
        return None
    return Revision(commit=commit, dirty=bool(changes))


def _git(git: str, root: Path, *arguments: str) -> str:
    # git first runs in whichever repository encloses the project, whose fsmonitor hook would run a command from its
    # config; no optional locks, so status never rewrites the index under another git process
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] # git from PATH with fixed arguments
        [git, "-c", "core.fsmonitor=false", "--no-optional-locks", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_revision(commit: str, origin: str) -> Revision:
    # the commit lands in the source link, so anything but a full hash could point the link elsewhere
    if not _COMMIT.fullmatch(commit):
        msg = f"{origin} must be a full lowercase hex commit hash of 40 or 64 characters, got {commit!r}"
        raise SettingsError(msg)
    return Revision(commit=commit, dirty=False)


__all__ = [
    "REVISION_FILE",
    "RevisionReader",
    "default_revision",
    "revision_reader",
]
