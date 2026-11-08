"""Main entry point."""

from __future__ import annotations

import sys

from ._cli._main import main

if __name__ == "__main__":
    main(sys.argv[1:])
