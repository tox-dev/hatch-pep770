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
from importlib.metadata import distributions
from itertools import starmap
from typing import TYPE_CHECKING, Final, Protocol

from installer.records import InvalidRecordEntry, RecordEntry, parse_record_file
from installer.utils import parse_metadata_file
from packaging.direct_url import DirectUrl, DirectUrlValidationError
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from python_sbom._errors import SettingsError
from python_sbom._model._inputs import BuildFacts, InstalledDistribution, Interpreter, RecordRow, Revision
from python_sbom._wheel._record import decode_digest

if TYPE_CHECKING:
    from collections.abc import Container, Sequence
    from importlib.metadata import Distribution, PackageMetadata
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
    found: Final[dict[str, tuple[Distribution, PackageMetadata]]] = {}
    for distribution in distributions(path=list(path)) if path is not None else distributions():
        try:
            metadata = distribution.metadata
        # a .dist-info without METADATA, which newer Pythons refuse to read
        except FileNotFoundError:  # pragma: >=3.15 cover
            continue
        # the first on the path is the one imports load, so a shadowed copy further down is left out
        if "Name" in metadata and "Version" in metadata:
            found.setdefault(canonicalize_name(metadata["Name"]), (distribution, metadata))
    return [
        InstalledDistribution(
            name=name,
            metadata=metadata,
            files=_recorded_files(distribution),
            depends_on=_depends_on(name, distribution, found),
        )
        for name, (distribution, metadata) in found.items()
    ]


def _recorded_files(distribution: Distribution) -> list[RecordRow]:
    # a platform wheel's files are built for this machine's OS and architecture, and an editable install's point at a
    # checkout, so listing either would tie the document to one machine
    if parse_metadata_file(distribution.read_text("WHEEL") or "")["Root-Is-Purelib"] != "true" or _editable(
        distribution
    ):
        return []
    # RECORD read once and as written: Distribution.files would stat every row to drop files missing on disk, and
    # build a path object for each, while the SBOM lists what the install recorded
    try:
        entries: Final[list[RecordEntry]] = list(
            starmap(RecordEntry.from_elements, parse_record_file((distribution.read_text("RECORD") or "").splitlines()))
        )
    except InvalidRecordEntry as error:
        warnings.warn(f"listed no files of {distribution.name}, its RECORD is malformed: {error}", stacklevel=2)
        return []
    rows: Final[list[RecordRow]] = []
    for entry in entries:
        if entry.hash_ is None or not _describes_distribution(entry.path):
            continue
        algorithm, digest = decode_digest(str(entry.hash_), entry.path)
        rows.append(RecordRow(path=entry.path, algorithm=algorithm, digest=digest, size=str(entry.size)))
    return rows


def _editable(distribution: Distribution) -> bool:
    if (text := distribution.read_text("direct_url.json")) is None:
        return False
    try:
        dir_info = DirectUrl.from_dict(json.loads(text)).dir_info
    # an installer that wrote the file wrong breaks no build: its files get listed, as for any other install
    except (ValueError, DirectUrlValidationError) as error:
        warnings.warn(f"read the direct_url.json of {distribution.name} as not editable: {error}", stacklevel=2)
        return False
    return dir_info is not None and dir_info.editable is True


def _describes_distribution(path: str) -> bool:
    # console-script launchers live outside site-packages and embed the environment's interpreter path; the installer
    # metadata names the frontend; uv's cache files hold paths and times; none of them says anything about the package
    directory, _, name = path.rpartition("/")
    return not (
        path.startswith("../")
        or (directory.endswith(".dist-info") and name in {"INSTALLER", "REQUESTED", "direct_url.json"})
        or re.fullmatch(r"uv_.*\.json", name)
    )


def _depends_on(name: str, distribution: Distribution, installed: Container[str]) -> list[str]:
    names: Final[set[str]] = set()
    for line in distribution.requires or []:
        try:
            requirement = Requirement(line)
        except InvalidRequirement as error:
            # old distributions declare requirements, such as "pytz (>dev)", that today's syntax rejects
            warnings.warn(f"left out the requirement {line!r} of {name}: {error}", stacklevel=2)
            continue
        if (required := canonicalize_name(requirement.name)) in installed and (
            requirement.marker is None or requirement.marker.evaluate()
        ):
            names.add(required)
    return sorted(names)


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
