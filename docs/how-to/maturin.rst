##################################
 Add an SBOM to a maturin project
##################################

maturin_ has written an :term:`SBOM` of a :term:`wheel`'s Rust crates since 1.12. python-sbom adds a second one with
what maturin's leaves out: the Python package, its declared dependencies, the build tools and the source revision. It
links to maturin's by file name and SHA-256, so a scanner that reads it also finds the crates. This guide sets that up
for each way a maturin project builds its wheels.

**********************
 What each SBOM holds
**********************

Both sit in the wheel's ``.dist-info/sboms`` directory, as :term:`PEP 770` allows:

.. list-table::
    :header-rows: 1

    - -
      - maturin's ``<crate>.cyclonedx.json``
      - python-sbom's ``<name>.cdx.json``
    - - Written by
      - `cargo-cyclonedx <https://github.com/CycloneDX/cyclonedx-rust-cargo>`_, inside maturin
      - python-sbom, after the wheel is written
    - - Identifies the wheel as
      - the Rust crate, ``pkg:cargo/<crate>@<version>``
      - the Python package, ``pkg:pypi/<name>@<version>``
    - - Components
      - the crates the extension or binary depends on, transitively, with the graph between them
      - the runtime dependencies the core metadata declares
    - - Also records
      -
      - supplier, authors and license; the build tools and interpreter; the :term:`source revision`; a link to every
        other SBOM in the directory, with its SHA-256

Keep maturin's: python-sbom does not list Rust crates, so turning it off with ``[tool.maturin.sbom] rust = false``
loses them. When maturin's repair copies shared libraries into the wheel, it adds a third SBOM, ``auditwheel.cdx.json``,
which python-sbom links the same way.

********************************
 Wheels a build frontend builds
********************************

pip_, uv_, ``python -m build`` and cibuildwheel_ build through the standard build interface. Make the
:term:`wrapper backend` the project's backend, keep maturin in the build requirements, and name it in
``[tool.python-sbom]``:

.. code-block:: toml

    [build-system]
    build-backend = 'python_sbom.backend'
    requires = ['maturin>=1.12,<2', 'python-sbom>=0.3']

    [tool.python-sbom]
    build-backend = 'maturin'
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every hook goes to maturin unchanged, so ``[tool.maturin]`` and ``--config-settings`` behave as before. Once maturin has
written the wheel, with its own SBOM inside, the wrapper adds python-sbom's. It runs in the build's isolated
environment, so the SBOM lists the maturin version the frontend installed.

.. code-block:: console

    $ uv build --wheel
    $ unzip -Z1 dist/*.whl '*/sboms/*'
    matex-1.0.dist-info/sboms/matex.cyclonedx.json
    matex-1.0.dist-info/sboms/matex.cdx.json

***************************************************
 Wheels ``maturin build`` or maturin-action builds
***************************************************

``maturin build`` and maturin-action_ call maturin's own command line, so the wrapper never runs. Describe those wheels
afterwards with ``python-sbom embed``, run from the project root so it finds ``[tool.python-sbom]``:

.. code-block:: console

    $ maturin build --release --out dist
    $ python-sbom embed dist/*.whl
    wrote matex-1.0.dist-info/sboms/matex.cdx.json into matex-1.0-py3-none-manylinux_2_34_x86_64.whl

``embed`` lists the packages of the environment it runs in as the build tools. maturin-action builds with a maturin
binary of its own, so install the same maturin version next to python-sbom, and the SBOM records the version that built
the wheel:

.. code-block:: yaml

    - uses: PyO3/maturin-action@v1
      with:
        maturin-version: 1.15.0
        args: --release --out dist
    - name: Write the SBOM into the wheels
      run: |
        python -m venv build-env
        build-env/bin/python -m pip install maturin==1.15.0 python-sbom==0.3.0
        build-env/bin/python-sbom embed dist/*.whl

On Linux, maturin-action builds inside a manylinux container and hands the ``dist`` directory back to the runner's user,
so ``embed`` can rewrite the wheels there. :doc:`/how-to/built-elsewhere` covers ``--build-env`` and the source
revision of a wheel built from an :term:`sdist`.

**********
 Check it
**********

``python-sbom validate`` checks maturin's ``.cyclonedx.json`` file as well as the ``.cdx.json`` ones:

.. code-block:: console

    $ python-sbom validate dist/
    SBOM in matex-1.0-py3-none-manylinux_2_34_x86_64.whl is valid

python-sbom's own SBOM gets the full check; maturin's and auditwheel's get the CycloneDX schema check alone, as
:doc:`/how-to/validate` describes.

************************************************
 Pitfall: a build backend in the project's tree
************************************************

A project whose ``[build-system]`` loads a backend from its own tree through ``backend-path``, for example one that
calls maturin and then post-processes the wheel, cannot use the wrapper: a frontend loads only a backend found on that
path. Run ``python-sbom embed`` on the finished wheels instead, as for ``maturin build``.

***********************************
 Pitfall: a repair outside maturin
***********************************

maturin applies its manylinux repair while it writes the wheel, so the file name is final. A later ``delocate`` or
``auditwheel repair`` renames the wheel, and the SBOM written before it names a file that is never published. Run
``python-sbom embed`` on the repaired wheel.
