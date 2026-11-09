"""Print a greeting the C extension builds."""

from __future__ import annotations

import sys

from ._greet import hello


def main() -> None:
    sys.stdout.write(f"{hello()}\n")
