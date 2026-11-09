###############################
 Use it with any other backend
###############################

Backends without a plugin interface get the :term:`SBOM` through ``python_sbom.backend``, a :term:`build backend` that
wraps yours. The table below links a guide with a complete project for each backend python-sbom is tested with; this
page covers how the wrapper works for those and any other backend. Make ``python_sbom.backend`` the project's backend,
keep yours in the build requirements, and name yours in ``[tool.python-sbom]``, as the meson-python project does:

.. literalinclude:: /examples/meson-python/pyproject.toml
    :language: toml
    :caption: pyproject.toml

``build-backend`` takes what ``[build-system] build-backend`` took before: a module, or ``module:object``. Every hook a
:term:`frontend <build frontend>` calls goes to your backend unchanged, ``--config-settings`` included, and the optional
hooks exist only when your backend defines them, so frontends behave as before. Once your backend has written a
:term:`wheel`, the wrapper writes the SBOM into it; once it has written an :term:`sdist`, it adds the :term:`source
revision`.

The wrapper runs inside the build's isolated environment, so the SBOM lists the tools that built the wheel, such as
meson-python, `meson <meson_>`_, ninja_ and patchelf, with the versions the frontend installed.

**************
 Each backend
**************

Use the module name from your current ``[build-system] build-backend``:

.. list-table::
    :header-rows: 1

    - - Backend
      - ``[tool.python-sbom] build-backend``
      - Guide
    - - meson-python_
      - ``mesonpy``
      - :doc:`/how-to/backends/meson-python`
    - - scikit-build-core_
      - ``scikit_build_core.build``
      - :doc:`/how-to/backends/scikit-build-core`
    - - maturin_
      - ``maturin``
      - :doc:`/how-to/backends/maturin`
    - - flit-core_
      - ``flit_core.buildapi``
      - :doc:`/how-to/backends/flit-core`
    - - poetry-core_
      - ``poetry.core.masonry.api``
      - :doc:`/how-to/backends/poetry-core`
    - - uv_build_
      - ``uv_build``
      - :doc:`/how-to/backends/uv-build`
    - - pdm-backend_, setuptools_
      - ``pdm.backend``, ``setuptools.build_meta``
      - :doc:`/how-to/backends/pdm-backend`, :doc:`/how-to/backends/setuptools`: use their plugin, and wrap them only
        when it cannot act

***********************************************
 Pitfall: builds that skip the build interface
***********************************************

The wrapper runs only when a frontend builds through the standard build interface: pip_, uv_, ``python -m build`` and
cibuildwheel_ do. Tools that call the backend's own command line do not: ``maturin build``, which maturin-action_ runs,
and ``meson`` called directly. Describe those wheels after the build, as :doc:`/how-to/built-elsewhere` shows.

*************************************
 Pitfall: a backend in your own tree
*************************************

The wrapper cannot wrap a backend the project ships in its own tree. Such a backend loads through ``[build-system]
backend-path``, and a frontend loads only a backend found on that path, so it refuses ``python_sbom.backend``, which
lives in the build environment. Describe those wheels after the build, as :doc:`/how-to/built-elsewhere` shows.

*************************************************
 Pitfall: tools that rename the wheel afterwards
*************************************************

``auditwheel repair`` renames a wheel to its manylinux tag, ``delocate`` can change its macOS tag, and both may copy
shared libraries into it, so the SBOM the wrapper wrote can name the old file and misses those libraries. Run ``python-sbom embed`` on the repaired
wheel, as :doc:`/how-to/built-elsewhere` shows.
