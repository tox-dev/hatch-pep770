"""The setuptools plugin, which writes the SBOM into every wheel setuptools builds."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.sdist import sdist

from ._collect import REVISION_FILE, default_revision, revision_record
from ._errors import SbomError

if TYPE_CHECKING:
    from setuptools.dist import Distribution

    from ._model import Revision


def finalize_distribution_options(distribution: Distribution) -> None:
    """
    Wrap the wheel and sdist commands of a project that asks for an SBOM.

    :param distribution: the distribution setuptools is about to build
    :raises SbomError: when the project's pyproject.toml is not valid TOML or replaces the wheel or sdist command, or
        the wheel command writes no wheel

    """
    # setuptools runs every build from the project directory
    root = Path.cwd()
    try:
        loaded = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except FileNotFoundError:  # a setup.py-only project, which cannot ask
        return
    except tomllib.TOMLDecodeError as error:
        msg = f"{root / 'pyproject.toml'} is not valid TOML: {error}"
        raise SbomError(msg) from error
    if "python-sbom" not in (tools := loaded.get("tool", {})):
        return
    # setuptools applies these after this plugin ran, so they would replace its commands and drop the SBOM unnoticed
    if replaced := sorted({"bdist_wheel", "sdist"} & set(tools.get("setuptools", {}).get("cmdclass", {}))):
        msg = (
            f"[tool.setuptools.cmdclass] replaces {', '.join(replaced)} after python-sbom wraps it, so the build would"
            " carry no SBOM; pass the command to setup(cmdclass=...) in setup.py, or wrap setuptools.build_meta with"
            " python_sbom.backend"
        )
        raise SbomError(msg)
    wheel_base = distribution.cmdclass.get("bdist_wheel", bdist_wheel)

    class SbomWheel(wheel_base):
        def run(self) -> None:
            from ._generate import embed_built  # ruff: ignore[import-outside-top-level] # wheels only

            # read before this command writes into build/; a checkout that does not ignore build/ or the egg-info
            # directory an earlier step wrote reads as dirty
            revision = default_revision(root)
            super().run()
            # bdist_wheel lists the wheel it wrote for the upload command; editable wheels never run this command
            if not (wheels := [entry[2] for entry in self.distribution.dist_files if entry[0] == "bdist_wheel"]):
                msg = f"{wheel_base.__qualname__} wrote no wheel to describe"
                raise SbomError(msg)
            embed_built(Path(wheels[-1]), root, revision)

    class SbomSdist(distribution.cmdclass.get("sdist", sdist)):
        _revision: Revision | None = None

        def run(self) -> None:
            # read before this command writes its egg-info, which a checkout may not ignore
            self._revision = default_revision(root)
            super().run()

        def make_release_tree(self, base_dir: str, files: list[str]) -> None:
            super().make_release_tree(base_dir, files)
            if (record := revision_record(self._revision)) is not None:
                (Path(base_dir) / REVISION_FILE).write_bytes(record)

    distribution.cmdclass.update(bdist_wheel=SbomWheel, sdist=SbomSdist)


__all__ = [
    "finalize_distribution_options",
]
