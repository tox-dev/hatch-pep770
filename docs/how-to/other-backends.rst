###############################
 Use it with any other backend
###############################

Backends without a plugin interface, such as meson-python, maturin, scikit-build-core, flit-core, poetry-core and
uv_build, get the SBOM through ``python_sbom.backend``, a build backend that wraps yours. Make it the project's backend,
keep yours in the build requirements, and name yours in ``[tool.python-sbom]``:

.. code-block:: toml

    [build-system]
    build-backend = 'python_sbom.backend'
    requires = ['meson-python>=0.18', 'meson>=1.6', 'ninja', 'python-sbom>=0.2']

    [tool.python-sbom]
    build-backend = 'mesonpy'
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

``build-backend`` takes what ``[build-system] build-backend`` took before: a module, or ``module:object``. Every hook a
frontend calls goes to your backend unchanged, ``--config-settings`` included, and the optional hooks exist only when
your backend defines them, so frontends behave as before. Once your backend has written a wheel, the wrapper writes the
SBOM into it; once it has written an sdist, it adds the source revision.

The wrapper runs inside the build's isolated environment, so the SBOM lists the tools that built the wheel, such as
meson-python, meson, ninja and patchelf, with the versions the frontend installed.

**************
 Each backend
**************

Use the module name from your current ``[build-system] build-backend``:

.. list-table::
    :header-rows: 1

    * - Backend
      - ``[tool.python-sbom] build-backend``
      - Notes
    * - `meson-python <https://meson-python.readthedocs.io/>`_
      - ``mesonpy``
      - Its sdist step needs a git or Mercurial checkout, as without the wrapper.
    * - `maturin <https://www.maturin.rs/>`_
      - ``maturin``
      - maturin writes its own SBOM of the Rust crates next to python-sbom's; see below.
    * - `scikit-build-core <https://scikit-build-core.readthedocs.io/>`_
      - ``scikit_build_core.build``
      - A project built with hatchling and scikit-build-core's hatch plugin uses :doc:`/how-to/hatchling` instead.
    * - `flit-core <https://flit.pypa.io/>`_
      - ``flit_core.buildapi``
      -
    * - `poetry-core <https://python-poetry.org/docs/pyproject/>`_
      - ``poetry.core.masonry.api``
      -
    * - `uv_build <https://docs.astral.sh/uv/concepts/build-backend/>`_
      - ``uv_build``
      - ``uv build`` builds a uv_build project in its own process, skipping the build interface; with the wrapper as the
        backend, it calls the build interface, so the wrapper runs.
    * - pdm-backend, setuptools
      - ``pdm.backend``, ``setuptools.build_meta``
      - Use :doc:`/how-to/pdm-backend` or :doc:`/how-to/setuptools` instead; wrap them only when the plugin cannot act.

maturin's own SBOM
==================

`maturin writes a CycloneDX SBOM <https://www.maturin.rs/sbom>`_ of the Rust crates a wheel links, as
``<crate>.cyclonedx.json``. PEP 770 allows several SBOMs per wheel, so python-sbom's ``<name>.cdx.json`` sits next to it:
maturin's lists the crates, python-sbom's the wheel's files, metadata, build tools and source revision.

***********************************************
 Pitfall: builds that skip the build interface
***********************************************

The wrapper runs only when a frontend builds through the standard build interface: pip, uv, ``python -m build`` and
cibuildwheel do. Tools that call the backend's own command line do not: ``maturin build``, which `maturin-action
<https://github.com/PyO3/maturin-action>`_ runs, and ``meson`` called directly. Describe those wheels after the build, as
:doc:`/how-to/built-elsewhere` shows.

*************************************
 Pitfall: a backend in your own tree
*************************************

The wrapper cannot wrap a backend the project ships in its own tree. Such a backend loads through ``[build-system]
backend-path``, and a frontend loads only a backend found on that path, so it refuses ``python_sbom.backend``, which
lives in the build environment. Describe those wheels after the build, as :doc:`/how-to/built-elsewhere` shows.

*************************************************
 Pitfall: tools that rename the wheel afterwards
*************************************************

``auditwheel repair`` and ``delocate`` rename a wheel to its final platform tag and may copy shared libraries into it, so
the SBOM the wrapper wrote names the old file and misses those libraries. Run ``python-sbom embed`` on the repaired
wheel, as :doc:`/how-to/built-elsewhere` shows.
