from __future__ import annotations

from typing import Final

# the Python versions that receive each bundled wheel, by distribution name; the build hook reads it without importing
_BUNDLE_SUPPORT: Final[dict[str, dict[str, str]]] = {
    "3.14": {"pip": "pip-1.0-py3-none-any.whl"},
    "3.15": {"pip": "pip-1.0-py3-none-any.whl"},
}
