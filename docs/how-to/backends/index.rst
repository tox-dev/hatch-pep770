###############################
 Set it up for a build backend
###############################

Each guide adds the :term:`SBOM` to the :term:`wheels <wheel>` one :term:`build backend` writes. It shows one of
:example:`the example projects <>` and the commands that build and check its wheel. hatchling_, pdm-backend_ and
setuptools_ load python-sbom as a plugin; the others get the SBOM through the :term:`wrapper backend`, and
:doc:`other-backends` covers a backend without a guide of its own.

.. toctree::
    :maxdepth: 1

    hatchling
    pdm-backend
    setuptools
    meson-python
    scikit-build-core
    maturin
    flit-core
    poetry-core
    uv-build
    other-backends
