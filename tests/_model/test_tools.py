from __future__ import annotations

import dataclasses
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._model._inputs import InstalledDistribution, RecordRow
from python_sbom._model._metadata import parse_metadata
from python_sbom._model._tools import script_tool, tool_components

if TYPE_CHECKING:
    from python_sbom._model._inputs import (  # simplint: ignore[private-import-path]  # test uses internal model
        BuildFacts,
    )


def test_tools_list_interpreter_then_distributions_by_name(facts: BuildFacts) -> None:
    row = RecordRow(path="zeta/__init__.py", algorithm="SHA-256", digest="ab" * 32, size="0")
    distributions = [
        InstalledDistribution(
            name="zeta", metadata=parse_metadata("Name: Zeta\nVersion: 2\n"), files=[row], depends_on=[]
        ),
        InstalledDistribution(
            name="alpha", metadata=parse_metadata("Name: alpha\nVersion: 1\n"), files=[], depends_on=["zeta"]
        ),
    ]
    tools, dependencies = tool_components(dataclasses.replace(facts, distributions=distributions))
    assert tools[1:] == [
        {
            "type": "library",
            "bom-ref": "tool:pkg:pypi/alpha@1",
            "name": "alpha",
            "version": "1",
            "purl": "pkg:pypi/alpha@1",
            "externalReferences": [],
            "properties": [],
        },
        {
            "type": "library",
            "bom-ref": "tool:pkg:pypi/zeta@2",
            "name": "Zeta",
            "version": "2",
            "purl": "pkg:pypi/zeta@2",
            "externalReferences": [],
            "properties": [],
            "components": [
                {
                    "type": "file",
                    "bom-ref": "tool:pkg:pypi/zeta@2#zeta/__init__.py",
                    "name": "zeta/__init__.py",
                    "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
                    "properties": [{"name": "size", "value": "0"}],
                }
            ],
        },
    ]
    assert dependencies == [
        {"ref": "tool:pkg:pypi/alpha@1", "dependsOn": ["tool:pkg:pypi/zeta@2"]},
        {"ref": "tool:pkg:pypi/zeta@2", "dependsOn": []},
    ]


def test_tool_bom_ref_and_purl_agree(facts: BuildFacts) -> None:
    # the distribution is keyed by its normalized name, while its metadata spells it with a dot
    tool = InstalledDistribution(
        name="boolean-py", metadata=parse_metadata("Name: boolean.py\nVersion: 5.0\n"), files=[], depends_on=[]
    )
    (_, component), _ = tool_components(dataclasses.replace(facts, distributions=[tool]))
    assert (component["bom-ref"], component.get("purl")) == ("tool:pkg:pypi/boolean-py@5.0", "pkg:pypi/boolean-py@5.0")


def test_script_tool_with_link() -> None:
    tool = script_tool(PurePosixPath("build/hook.py"), "ef" * 32, "1.0", "https://example.com/hook.py")
    assert tool == {
        "type": "application",
        "bom-ref": "tool:build/hook.py",
        "name": "hook.py",
        "version": "1.0",
        "hashes": [{"alg": "SHA-256", "content": "ef" * 32}],
        "externalReferences": [{"type": "vcs", "url": "https://example.com/hook.py"}],
    }


def test_script_tool_without_link() -> None:
    assert "externalReferences" not in script_tool(PurePosixPath("hook.py"), "ef" * 32, "1.0", None)
