####################################################
 Describe a wheel built outside the build interface
####################################################

Some wheels never pass through a python-sbom plugin or the wrapper backend: maturin-action calls ``maturin build``
directly, and ``auditwheel repair`` or ``delocate`` rename a wheel after the build and may copy libraries into it.
``python-sbom embed`` describes such a wheel after the fact. It writes the same document the plugins write, adds its
``RECORD`` row, keeps every other entry of the wheel as it was, and replaces an SBOM python-sbom wrote before.

***********************
 Embed after the build
***********************

Run it from the project root, so it finds ``[tool.python-sbom]``:

.. code-block:: console

    $ maturin build --release --out dist
    $ python-sbom embed dist/*.whl
    wrote matex-1.0.dist-info/sboms/matex.cdx.json into matex-1.0-py3-none-manylinux_2_17_x86_64.whl

*****************************
 Record the real build tools
*****************************

``embed`` lists the packages of the environment ``--build-env`` names, by default the one it runs in, and always the
interpreter it runs on. Unless that is the environment the wheel was built in, the record does not match the real build.
Either build without isolation in the environment ``embed`` runs in, installed from the same lock:

.. code-block:: console

    $ python -m pip install build python-sbom meson-python meson ninja patchelf
    $ python -m build --wheel --no-isolation
    $ python-sbom embed dist/*.whl

or install the build requirements into an environment of their own and point ``--build-env`` at its ``site-packages``:

.. code-block:: console

    $ python -m venv build-env && build-env/bin/pip install maturin
    $ python-sbom embed dist/*.whl --build-env build-env/lib/python3.15/site-packages

****************
 After a repair
****************

Run ``embed`` on the repaired wheel, so the SBOM names the file you publish:

.. code-block:: console

    $ auditwheel repair dist/*.whl --wheel-dir wheelhouse
    $ python-sbom embed wheelhouse/*.whl

auditwheel's own SBOM, ``auditwheel.cdx.json``, stays in the wheel next to python-sbom's.

**************************
 Name the source revision
**************************

``embed`` reads the commit from the checkout it runs in. A wheel built from an sdist elsewhere names its commit through
``--commit`` or the ``PYTHON_SBOM_COMMIT`` environment variable; :doc:`/reference/configuration` lists the order in
which python-sbom looks for it.
