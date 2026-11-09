"""The size limits that keep a hostile SBOM from exhausting memory or time."""

from __future__ import annotations

from typing import Final

# every check takes time in proportion to the count, so the cap bounds the work an untrusted document can ask for, far
# above the few thousand components a wheel with its build tools' files lists
MAX_COMPONENTS: Final[int] = 100_000
# an exception's message, or a schema error's, can quote the hostile value that caused it, which runs to megabytes
MAX_TEXT: Final[int] = 200


def byte_limit(max_components: int) -> int:
    # python-sbom writes about 540 bytes per component, since every file of the wheel and of its build tools is one; a
    # KiB each leaves room for documents with fuller components, plus a MiB for the metadata, dependencies and
    # formulation beside them, while tying what the JSON parser may be asked to hold to the component cap
    return 1024 * 1024 + max_components * 1024


__all__ = [
    "MAX_COMPONENTS",
    "MAX_TEXT",
    "byte_limit",
]
