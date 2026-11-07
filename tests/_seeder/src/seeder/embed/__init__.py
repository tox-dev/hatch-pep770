from __future__ import annotations

from pathlib import Path

# the layout of virtualenv's seed/wheels/embed/__init__.py: another assignment comes before the table
BUNDLE_FOLDER = Path(__file__).absolute().parent
BUNDLE_SUPPORT = {
    "3.14": {"pip": "pip-1.0-py3-none-any.whl"},
    "3.15": {"pip": "pip-1.0-py3-none-any.whl"},
}
