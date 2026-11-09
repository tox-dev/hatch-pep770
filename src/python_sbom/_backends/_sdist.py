from __future__ import annotations

import gzip
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path
from typing import Final

from python_sbom._errors import SbomError


def add_to_sdist(sdist: Path, name: str, content: bytes) -> None:
    # the backend wrote the sdist already, so the file joins it under the sdist's top directory; a backend that added
    # the file itself, such as one running python-sbom's own plugin, keeps its copy
    with tarfile.open(sdist, "r:gz") as source:
        members: Final[list[tarfile.TarInfo]] = source.getmembers()
        if not members or (top := members[0].name.split("/", 1)[0]) in {"", ".", ".."}:
            msg = f"{sdist} has no top-level directory to add {name} to"
            raise SbomError(msg)
        if (target := f"{top}/{name}") in {member.name for member in members}:
            return
        # the sdist's own newest time, so the added entry keeps a reproducible build reproducible
        added: Final[tarfile.TarInfo] = tarfile.TarInfo(target)
        added.size = len(content)
        added.mtime = max(member.mtime for member in members)
        added.mode = stat.S_IFREG | 0o644
        # the gzip header keeps the time the backend gave it, bytes 4 to 8 of the header, for the same reason
        with sdist.open("rb") as existing:
            header = existing.read(8)
        descriptor, temporary = tempfile.mkstemp(dir=sdist.parent, prefix=".python-sbom-", suffix=".tmp")
        os.close(descriptor)
        try:
            with (
                Path(temporary).open("wb") as raw,
                gzip.GzipFile(fileobj=raw, mode="wb", mtime=int.from_bytes(header[4:8], "little")) as compressed,
                tarfile.open(fileobj=compressed, mode="w", format=source.format) as rewritten,
            ):
                for member in members:
                    rewritten.addfile(member, source.extractfile(member) if member.isfile() else None)
                rewritten.addfile(added, io.BytesIO(content))
            Path(temporary).chmod(stat.S_IMODE(sdist.stat().st_mode))
            Path(temporary).replace(sdist)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise


__all__ = [
    "add_to_sdist",
]
