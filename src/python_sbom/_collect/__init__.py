"""What the edge reads: settings, build facts, the source revision, the project tree, the artifact and the provider."""

from __future__ import annotations

from ._revision import REVISION_FILE, default_revision, revision_record
from ._settings import settings_from_pyproject

__all__ = [
    "REVISION_FILE",
    "default_revision",
    "revision_record",
    "settings_from_pyproject",
]
