from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from python_sbom import BuildFacts, document, git_revision

if TYPE_CHECKING:
    from pathlib import Path

    from python_sbom import Body, Component, Document


def describe_zipapp(root: Path, version: str) -> Document:  # simplint: ignore[SMP408]  # the docs include it
    # the build toolchain and time, recorded the same way the wheel SBOM records them
    facts = BuildFacts.collect(root, git_revision)
    zipapp: Component = {
        "type": "application",
        "bom-ref": f"pkg:generic/virtualenv.pyz@{version}",
        "name": "virtualenv.pyz",
        "version": version,
    }
    body: Body = {
        "metadata": {
            "timestamp": facts.timestamp,
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": facts.tools},
            "component": zipapp,
        },
        "components": [],
        "dependencies": [{"ref": zipapp["bom-ref"], "dependsOn": []}, *facts.tool_dependencies],
    }
    return document(body, uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/pypa/virtualenv/sboms"))


__all__ = [
    "describe_zipapp",
]
