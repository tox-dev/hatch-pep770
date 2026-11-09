Use it with pdm-backend
=======================

python-sbom ships a `pdm-backend <https://backend.pdm-project.org/>`_ build hook, registered in pdm-backend's
``pdm.build.hook`` entry point group. Add python-sbom to the build requirements, with the ``pdm`` extra, and add a
``[tool.python-sbom]`` table, empty or not:

.. code-block:: toml

    [build-system]
    build-backend = 'pdm.backend'
    requires = ['pdm-backend>=2.4', 'python-sbom[pdm]>=0.2']

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every wheel you build now carries the SBOM, and every sdist the source revision. An editable wheel carries none.

pdm-backend loads every hook installed in the build environment, so the table is what turns this one on: a project
without ``[tool.python-sbom]`` builds as before even when python-sbom is installed.

The hook runs in pdm-backend's ``pdm_build_finalize`` step, once the wheel is written, so the document describes the
final file name and metadata. When ``SOURCE_DATE_EPOCH`` is unset, pdm-backend dates every wheel entry 2016-01-01, and
the SBOM takes the same time, so a rebuild reproduces both.

A project with its own ``pdm_build.py`` keeps it; both hooks run.
