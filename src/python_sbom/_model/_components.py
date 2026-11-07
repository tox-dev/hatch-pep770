from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import PackageMetadata
    from pathlib import PurePosixPath

    from ._inputs import BundledWheel
    from ._types import Component, OrganizationalEntity, Property


def bundled_wheel_component(
    wheel: BundledWheel, namespace: str, properties: list[Property], supplier: OrganizationalEntity | None
) -> Component:
    return _core.bundled_wheel_component(wheel, namespace, properties, supplier)


def component_from_metadata(metadata: PackageMetadata | Message | _core.Metadata) -> Component:
    return _core.component_from_metadata(metadata)


def file_component_from_bytes(parent_ref: str, name: str, content: bytes) -> Component:
    return _core.file_component_from_bytes(parent_ref, name, content)


def script_tool(path: PurePosixPath, sha256: str, version: str, link: str | None) -> Component:
    return _core.script_tool(path, sha256, version, link)


__all__ = [
    "bundled_wheel_component",
    "component_from_metadata",
    "file_component_from_bytes",
    "script_tool",
]
