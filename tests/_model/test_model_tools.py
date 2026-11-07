from __future__ import annotations

import dataclasses
from email import message_from_string
from typing import TYPE_CHECKING

from python_sbom import InstalledDistribution, RecordRow, tool_components

if TYPE_CHECKING:
    from python_sbom import BuildFacts


def test_tools_list_interpreter_then_distributions_by_name(facts: BuildFacts) -> None:
    row = RecordRow(path="zeta/__init__.py", algorithm="SHA-256", digest="ab" * 32, size="0")
    distributions = [
        InstalledDistribution(metadata=message_from_string("Name: Zeta\nVersion: 2\n"), files=[row], depends_on=[]),
        InstalledDistribution(metadata=message_from_string("Name: alpha\nVersion: 1\n"), files=[], depends_on=["zeta"]),
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
