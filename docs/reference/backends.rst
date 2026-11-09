####################
 Supported backends
####################

Each :term:`build backend` gets the :term:`SBOM` through one integration. :doc:`/concepts/backends` says why each gets
the one it does.

.. list-table::
    :header-rows: 1

    - - Backend
      - Integration
      - Turned on by
      - Install
      - Guide
    - - hatchling_
      - :term:`build hook`, ``hatch`` entry point group
      - ``[tool.hatch.build.hooks.python-sbom]``
      - ``python-sbom[hatch]``
      - :doc:`/how-to/backends/hatchling`
    - - pdm-backend_
      - build hook, ``pdm.build.hook`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[pdm]``
      - :doc:`/how-to/backends/pdm-backend`
    - - setuptools_
      - plugin, ``setuptools.finalize_distribution_options`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[setuptools]``
      - :doc:`/how-to/backends/setuptools`
    - - meson-python_, maturin_, scikit-build-core_, flit-core_, poetry-core_, uv_build_
      - ``python_sbom.backend``, which wraps the backend
      - ``[build-system] build-backend = 'python_sbom.backend'`` and ``[tool.python-sbom] build-backend``
      - ``python-sbom``
      - :doc:`/how-to/backends/meson-python`, :doc:`/how-to/backends/maturin`,
        :doc:`/how-to/backends/scikit-build-core`, :doc:`/how-to/backends/flit-core`,
        :doc:`/how-to/backends/poetry-core`, :doc:`/how-to/backends/uv-build`; any other:
        :doc:`/how-to/backends/other-backends`
    - - any, for a :term:`wheel` built outside the build interface or renamed after it
      - ``python-sbom embed``
      - running the command
      - ``python-sbom``
      - :doc:`/how-to/built-elsewhere`

Every integration writes the same document, from the same ``[tool.python-sbom]`` options, and records the source
revision in the :term:`sdists <sdist>` it builds. None writes an SBOM into an editable wheel, which carries no code.
