from __future__ import annotations

import json
import os
import platform
import sys
import time
import warnings
from importlib.metadata import distributions
from itertools import starmap
from typing import TYPE_CHECKING, Final

from installer.records import InvalidRecordEntry, RecordEntry, parse_record_file
from installer.utils import parse_metadata_file
from packaging.direct_url import DirectUrl, DirectUrlValidationError
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from python_sbom._errors import SettingsError
from python_sbom._model._inputs import BuildFacts, InstalledDistribution, Interpreter, RecordRow
from python_sbom._model._metadata import parse_metadata
from python_sbom._wheel._record import decode_digest

if TYPE_CHECKING:
    from collections.abc import Container, Sequence
    from importlib.metadata import Distribution
    from pathlib import Path

    from python_sbom._model._metadata import CoreMetadata

    from ._revision import RevisionReader


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
    found: Final[dict[str, tuple[Distribution, CoreMetadata]]] = {}
    for distribution in distributions(path=list(path)) if path is not None else distributions():
        # where Distribution.metadata looks, a .dist-info's METADATA, then an .egg-info's PKG-INFO or the file itself
        text = distribution.read_text("METADATA") or distribution.read_text("PKG-INFO") or distribution.read_text("")
        # the first on the path is the one imports load, so a shadowed copy further down is left out
        if (metadata := parse_metadata(text or "")).name and metadata.version:
            found.setdefault(canonicalize_name(metadata.name), (distribution, metadata))
    return [
        InstalledDistribution(
            name=name,
            metadata=metadata,
            files=_recorded_files(distribution),
            depends_on=_depends_on(name, distribution, metadata, found),
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
        or (name.startswith("uv_") and name.endswith(".json"))
    )


def _depends_on(name: str, distribution: Distribution, metadata: CoreMetadata, installed: Container[str]) -> list[str]:
    names: Final[set[str]] = set()
    # an .egg-info states its requirements in requires.txt, which Distribution.requires reads
    for line in metadata.values("requires_dist") or distribution.requires or []:
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


__all__ = [
    "collect_facts",
]
