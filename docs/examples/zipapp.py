from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from email.parser import Parser
from typing import TYPE_CHECKING

from python_sbom import (
    collect_facts,
    default_revision,
    document,
    file_component_from_bytes,
    formulation,
    project_identity,
    settings_from_pyproject,
    tool_components,
)

if TYPE_CHECKING:
    from pathlib import Path

    from python_sbom import Body, Component, Document


def describe_zipapp(root: Path, zipapp: Path) -> Document:  # simplint: ignore[SMP408] # the docs include it
    with zipfile.ZipFile(zipapp) as archive:
        members = sorted(name for name in archive.namelist() if not name.endswith("/"))
        metadata = Parser().parsestr(
            archive.read(next(name for name in members if name.endswith(".dist-info/METADATA"))).decode()
        )
        app: Component = {
            "type": "application",
            "bom-ref": f"pkg:generic/{zipapp.name}@{metadata['Version']}",
            "name": zipapp.name,
            "version": metadata["Version"],
        }
        app["components"] = [file_component_from_bytes(app["bom-ref"], name, archive.read(name)) for name in members]
    # the build toolchain, time and serial namespace, taken the way the wheel SBOM takes them
    facts = collect_facts(root, default_revision, None, None)
    identity = project_identity(metadata, settings_from_pyproject(root, {}))
    tools, tool_dependencies = tool_components(facts)
    body: Body = {
        "metadata": {
            "timestamp": datetime.fromtimestamp(facts.epoch, UTC).isoformat(),
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": tools},
            "component": app,
            # naming the document's file marks it as built the python-sbom way, so validate checks it in full
            "properties": [{"name": f"{identity.namespace}:sbom:file", "value": f"{zipapp.name}.cdx.json"}],
        },
        "components": [],
        "dependencies": [{"ref": app["bom-ref"], "dependsOn": []}, *tool_dependencies],
        "formulation": [formulation("zipapp-build", "build the zipapp", tools, app["bom-ref"], facts)],
    }
    return document(body, identity.serial_namespace)


__all__ = [
    "describe_zipapp",
]
