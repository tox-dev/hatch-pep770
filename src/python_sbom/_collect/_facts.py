from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] # runs git to read the source revision
import sys
import time
import warnings
from typing import TYPE_CHECKING, Final, Protocol

from python_sbom import _core
from python_sbom._errors import SettingsError
from python_sbom._model._inputs import BuildFacts, InstalledDistribution, Interpreter, Revision

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

#: the file an sdist carries its source revision in, as ``node: <commit>``, for the wheel built from it
REVISION_FILE: Final[str] = ".python-sbom-revision"
_COMMIT: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class RevisionReader(Protocol):
    def __call__(self, root: Path, /) -> Revision | None: ...


def collect_facts(
    root: Path, revision: RevisionReader, *, path: Sequence[str] | None = None, default_epoch: int | None = None
) -> BuildFacts:
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
    # read straight from each .dist-info by the core, in parallel; the first on the path is the one imports load, so a
    # shadowed copy further down is left out
    found, raised = _core.collect_distributions(list(sys.path if path is None else path), _marker_environment())
    for warned in raised:
        for warning in warned:
            warnings.warn(_message(warning), stacklevel=3)
    return [
        InstalledDistribution(name=name, metadata=metadata, files=files, depends_on=depends_on)
        for name, metadata, files, depends_on in found
    ]


def _message(warning: str | tuple[str, str]) -> str:
    if isinstance(warning, str):
        return warning
    # json words its own errors, so the core leaves a direct_url.json that does not parse to it
    name, text = warning
    try:
        json.loads(text)
    except ValueError as error:
        return f"read the direct_url.json of {name} as not editable: {error}"
    return f"read the direct_url.json of {name} as not editable"  # pragma: no cover # the core parses what json does


def _marker_environment() -> dict[str, str]:
    # packaging's default_environment, built without importing packaging
    info = sys.implementation.version
    implementation_version = f"{info.major}.{info.minor}.{info.micro}"
    if info.releaselevel != "final":  # pragma: no cover # depends on the interpreter running the tests
        implementation_version += f"{info.releaselevel[0]}{info.serial}"
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": implementation_version,
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    }


def default_revision(root: Path, /) -> Revision | None:
    # the variable exists for builds from an sdist, so it wins over whatever checkout the sdist was unpacked into
    if commit := os.environ.get("PYTHON_SBOM_COMMIT"):
        return commit_revision(commit, "PYTHON_SBOM_COMMIT")
    if (found := git_revision(root)) is not None:
        return found
    # the sdist build wrote it from the revision it resolved, so it is at least as exact as an archival file
    if (recorded := root / REVISION_FILE).is_file():
        return commit_revision(recorded.read_text(encoding="utf-8").strip().removeprefix("node: "), REVISION_FILE)
    archival = root / ".git_archival.txt"
    if archival.is_file() and (
        match := re.search(rf"^node: ({_COMMIT.pattern})$", archival.read_text(encoding="utf-8"), re.MULTILINE)
    ):
        return Revision(commit=match[1], dirty=False)
    return None


def commit_revision(commit: str, origin: str) -> Revision:
    # the commit lands in the source link, so anything but a full hash could point the link elsewhere
    if not _COMMIT.fullmatch(commit):
        msg = f"{origin} must be a full lowercase hex commit hash of 40 or 64 characters, got {commit!r}"
        raise SettingsError(msg)
    return Revision(commit=commit, dirty=False)


def git_revision(root: Path, /) -> Revision | None:
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


__all__ = [
    "REVISION_FILE",
    "RevisionReader",
    "collect_facts",
    "commit_revision",
    "default_revision",
    "git_revision",
]
