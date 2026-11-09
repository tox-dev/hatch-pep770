###############################
 Use it with any other backend
###############################

Backends without a plugin interface, such as meson-python_, maturin_, scikit-build-core_, flit-core_, poetry-core_ and
uv_build_, get the :term:`SBOM` through ``python_sbom.backend``, a :term:`build backend` that wraps yours. Make it the
project's backend, keep yours in the build requirements, and name yours in ``[tool.python-sbom]``:

.. code-block:: toml

    [build-system]
    build-backend = 'python_sbom.backend'
    requires = ['meson-python>=0.18', 'meson>=1.6', 'ninja', 'python-sbom>=0.2']

    [tool.python-sbom]
    build-backend = 'mesonpy'
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

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
      - Notes
    - - `meson-python <https://meson-python.readthedocs.io/>`_
      - ``mesonpy``
      - Its sdist step needs a git_ or Mercurial checkout, as without the wrapper.
    - - maturin_
      - ``maturin``
      - maturin writes its own SBOM of the Rust crates next to python-sbom's; :doc:`/how-to/maturin` covers both.
    - - scikit-build-core_
      - ``scikit_build_core.build``
      - A project built with hatchling_ and scikit-build-core's hatch plugin uses :doc:`/how-to/hatchling` instead.
    - - flit-core_
      - ``flit_core.buildapi``
      -
    - - `poetry-core <https://python-poetry.org/docs/pyproject/>`_
      - ``poetry.core.masonry.api``
      -
    - - uv_build_
      - ``uv_build``
      - ``uv build`` builds a uv_build project in its own process, skipping the build interface; with the wrapper as the
        backend, it calls the build interface, so the wrapper runs.
    - - pdm-backend_, setuptools_
      - ``pdm.backend``, ``setuptools.build_meta``
      - Use :doc:`/how-to/pdm-backend` or :doc:`/how-to/setuptools` instead; wrap them only when the plugin cannot act.

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

``auditwheel repair`` and ``delocate`` rename a wheel to its final platform tag and may copy shared libraries into it,
so the SBOM the wrapper wrote names the old file and misses those libraries. Run ``python-sbom embed`` on the repaired
wheel, as :doc:`/how-to/built-elsewhere` shows.
