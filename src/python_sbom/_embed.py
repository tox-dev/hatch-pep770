from __future__ import annotations

import json
import os
import tempfile
import time
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import TYPE_CHECKING, Final

from hatchling.builders.utils import get_reproducible_timestamp

from ._cyclonedx import record_digest
from ._project import sbom_file_name

if TYPE_CHECKING:
    from ._project import Project


def embed(wheel: Path, project: Project) -> str:
    """
    Write the SBOM into a wheel some other build backend already built, as the build hook would have.

    The SBOM goes under ``.dist-info/sboms/`` with a ``RECORD`` row, replacing an SBOM of the same name. Every other
    entry keeps its name, order, timestamp and permissions, and the new entry takes its timestamp from
    ``SOURCE_DATE_EPOCH``, so embedding into the same wheel twice gives the same bytes.

    :param wheel: the wheel to rewrite in place
    :param project: the source tree the wheel was built from
    :returns: the SBOM's path inside the wheel

    """
    with zipfile.ZipFile(wheel) as archive:
        entries: Final[list[tuple[zipfile.ZipInfo, bytes]]] = [
            (info, archive.read(info)) for info in archive.infolist()
        ]
    dist_info: Final[str] = next(
        info.filename.split("/")[0]
        for info, _ in entries
        if info.filename.count("/") == 1 and info.filename.endswith(".dist-info/METADATA")
    )
    contents: Final[dict[str, bytes]] = {info.filename: content for info, content in entries}
    metadata = Parser().parsestr(contents[f"{dist_info}/METADATA"].decode("utf-8"))
    sbom: Final[str] = f"{dist_info}/sboms/{sbom_file_name(metadata)}"
    content: Final[bytes] = f"{json.dumps(project.describe(metadata, wheel.name), indent=2)}\n".encode()
    record: Final[str] = f"{dist_info}/RECORD"
    lines: Final[list[str]] = [
        line for line in contents[record].decode("utf-8").splitlines(keepends=True) if not line.startswith(f"{sbom},")
    ]
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    # the RECORD row of RECORD itself stays last
    at = next((index for index, line in enumerate(lines) if line.startswith(f"{record},")), len(lines))
    lines.insert(at, f"{sbom},{record_digest(content)},{len(content)}{newline}")
    entry = zipfile.ZipInfo(sbom, time.gmtime(max(get_reproducible_timestamp(), 315532800))[:6])  # zip starts at 1980
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = 0o644 << 16
    # written next to the wheel and moved over it, so a failure leaves the wheel as it was
    descriptor, temporary = tempfile.mkstemp(dir=wheel.parent, suffix=".whl")
    os.close(descriptor)
    with zipfile.ZipFile(temporary, "w") as archive:
        for info, data in entries:
            if info.filename == record:
                archive.writestr(entry, content)
                archive.writestr(info, "".join(lines).encode())
            elif info.filename != sbom:
                archive.writestr(info, data)
    Path(temporary).replace(wheel)
    return sbom


__all__ = [
    "embed",
]
