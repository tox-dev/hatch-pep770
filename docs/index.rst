python-sbom
===========

SBOMs for Python distributions. python-sbom writes a `CycloneDX <https://cyclonedx.org/>`_ 1.6 SBOM into every wheel
you build, at ``<name>-<version>.dist-info/sboms/<name>.cdx.json``. That is where `PEP 770
<https://peps.python.org/pep-0770/>`_ tells installers to keep SBOMs, so they land in the environment next to the
installed package, where scanners look for them.

Why a wheel needs its own SBOM
------------------------------

General-purpose scanners read the dependencies a package declares or the packages an environment has installed. They
cannot see a wheel your project ships as a data file, and they cannot say how the wheel was built. The SBOM this package
writes records both: the wheels you bundle, with their hashes, licenses and vendored packages, and the Python version
and packages of the build environment. A third party can use that record to rebuild the wheel and compare the bytes.

Quick start
-----------

For a project built with `hatchling <https://hatch.pypa.io/latest/>`_, add the hook to the build requirements and
enable it in ``pyproject.toml``:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['python-sbom>=0.1', 'hatchling>=1.28']

    [tool.hatch.build.hooks.python-sbom]

Every wheel you build now carries the SBOM. For a project built with another backend, such as meson-python, run
``python-sbom embed dist/*.whl`` after the build; :doc:`usage` shows both.

.. toctree::
   :maxdepth: 2

   usage
   extend
   explanation
   cli
   py_api
   changelog
   contributing
