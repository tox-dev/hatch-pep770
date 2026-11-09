"""Print a greeting the C extension builds."""

from __future__ import annotations

from ._greet import hello


def main() -> None:
    print(hello())
