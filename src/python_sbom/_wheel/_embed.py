from __future__ import annotations

import os
import tempfile
import time
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import TYPE_CHECKING, Final

from python_sbom._backend import Backend
from python_sbom._errors import WheelError
from python_sbom._model._components import record_digest

if TYPE_CHECKING:
    from email.message import Message

    from python_sbom._collect._facts import BuildFacts
    from python_sbom._collect._settings import Settings


class BuiltWheel(Backend):
    """
    A wheel some other build backend already built, such as meson-python, and the project it came from.

    :param wheel: the wheel, rewritten in place by :meth:`embed`
    :param root: the project directory the wheel was built from
    :param settings: the project's options, usually from ``[tool.python-sbom]``

    """

    def __init__(self, wheel: Path, root: Path, settings: Settings) -> None:
        self._wheel = wheel
        self._root = root
        self._settings = settings
        with zipfile.ZipFile(wheel) as archive:
            self._entries: Final[list[tuple[zipfile.ZipInfo, bytes]]] = [
                (info, archive.read(info)) for info in archive.infolist()
            ]
        if (
            dist_info := next(
                (
                    info.filename.split("/")[0]
                    for info, _ in self._entries
                    if info.filename.count("/") == 1 and info.filename.endswith(".dist-info/METADATA")
                ),
                None,
            )
        ) is None:
            msg = f"{wheel} has no .dist-info/METADATA, so it is not a wheel"
            raise WheelError(msg)
        self._dist_info: Final[str] = dist_info

    @property
    def root(self) -> Path:
        """The project directory the wheel was built from."""
        return self._root

    @property
    def settings(self) -> Settings:
        """The project's options."""
        return self._settings

    def metadata(self) -> Message:
        """
        Read the core metadata from the wheel.

        :returns: the parsed ``METADATA``

        """
        return Parser().parsestr(self._read(f"{self._dist_info}/METADATA").decode("utf-8"))

    def _read(self, name: str) -> bytes:
        return next(data for info, data in self._entries if info.filename == name)

    def wheel_name(self) -> str:
        """
        Return the wheel's file name.

        :returns: the file name

        """
        return self._wheel.name

    def embed(self, facts: BuildFacts) -> str:
        """
        Write the SBOM into the wheel under ``.dist-info/sboms/``, with a ``RECORD`` row.

        An SBOM of the same name is replaced. Every other entry keeps its name, order, timestamp and permissions, and
        the new one takes its timestamp from ``SOURCE_DATE_EPOCH``, so embedding into the same wheel twice gives the
        same bytes.

        :param facts: what the environment says about the build
        :returns: the SBOM's path inside the wheel

        """
        name, content = self.sbom(facts)
        sbom: Final[str] = f"{self._dist_info}/sboms/{name}"
        record: Final[str] = f"{self._dist_info}/RECORD"
        lines: Final[list[str]] = [
            line
            for line in self._read(record).decode("utf-8").splitlines(keepends=True)
            if not line.startswith(f"{sbom},")
        ]
        newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
        # the RECORD row of RECORD itself stays last
        at = next((index for index, line in enumerate(lines) if line.startswith(f"{record},")), len(lines))
        lines.insert(at, f"{sbom},{record_digest(content)},{len(content)}{newline}")
        entry = zipfile.ZipInfo(sbom, time.gmtime(max(facts.epoch, 315532800))[:6])  # zip timestamps start at 1980
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o644 << 16
        # written next to the wheel and moved over it, so a failure leaves the wheel as it was
        descriptor, temporary = tempfile.mkstemp(dir=self._wheel.parent, suffix=".whl")
        os.close(descriptor)
        with zipfile.ZipFile(temporary, "w") as archive:
            for info, data in self._entries:
                if info.filename == record:
                    archive.writestr(entry, content)
                    archive.writestr(info, "".join(lines).encode())
                elif info.filename != sbom:
                    archive.writestr(info, data)
        Path(temporary).replace(self._wheel)
        return sbom


__all__ = [
    "BuiltWheel",
]
