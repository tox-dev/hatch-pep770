Supported backends
==================

Each build backend gets the SBOM through one integration. :doc:`../explanation/backends` says why each gets the one it
does.

.. list-table::
    :header-rows: 1

    * - Backend
      - Integration
      - Turned on by
      - Install
      - Guide
    * - hatchling
      - build hook, ``hatch`` entry point group
      - ``[tool.hatch.build.hooks.python-sbom]``
      - ``python-sbom[hatch]``
      - :doc:`../how-to/hatchling`
    * - pdm-backend
      - build hook, ``pdm.build.hook`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[pdm]``
      - :doc:`../how-to/pdm-backend`
    * - setuptools
      - plugin, ``setuptools.finalize_distribution_options`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[setuptools]``
      - :doc:`../how-to/setuptools`
    * - meson-python, maturin, scikit-build-core, flit-core, poetry-core, uv_build
      - ``python_sbom.backend``, which wraps the backend
      - ``[build-system] build-backend = 'python_sbom.backend'`` and ``[tool.python-sbom] build-backend``
      - ``python-sbom``
      - :doc:`../how-to/other-backends`
    * - any, for a wheel built outside the build interface or renamed after it
      - ``python-sbom embed``
      - running the command
      - ``python-sbom``
      - :doc:`../how-to/built-elsewhere`

Every integration writes the same document, from the same ``[tool.python-sbom]`` options, and records the source
revision in the sdists it builds. None writes an SBOM into an editable wheel, which carries no code.
