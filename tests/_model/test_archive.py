from __future__ import annotations

from pathlib import PurePosixPath

from python_sbom._model._archive import bundled_paths
from python_sbom._model._inputs import ArchiveTree


def test_bundled_paths_list_top_level_wheels_then_each_unpacked_wheel_with_its_own() -> None:
    tree = ArchiveTree(
        metadata={},
        owned={
            "": ["top.txt"],
            "lib/b/": ["lib/b/inner.whl", "lib/b/code.py"],
            "lib/a/": ["lib/a/code.py"],
        },
        loose=["z.whl", "readme.txt", "a.whl"],
        files={},
        bundled={},
    )
    assert bundled_paths(tree) == [
        PurePosixPath("z.whl"),
        PurePosixPath("a.whl"),
        PurePosixPath("lib/a"),
        PurePosixPath("lib/b"),
        PurePosixPath("lib/b/inner.whl"),
    ]
