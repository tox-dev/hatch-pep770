python-sbom
===========

SBOMs for Python distributions. python-sbom writes a `CycloneDX <https://cyclonedx.org/>`_ 1.6 SBOM into every wheel you
build, at ``<name>-<version>.dist-info/sboms/<name>.cdx.json``. That is where `PEP 770
<https://peps.python.org/pep-0770/>`_ tells installers to keep SBOMs, so they land in the environment next to the
installed package, where scanners look for them.

General-purpose scanners read the dependencies a package declares or the packages an environment has installed. They
cannot see a wheel your project ships as a data file, and they cannot say how the wheel was built. The SBOM python-sbom
writes records both: the wheels you bundle, with their hashes, licenses and vendored packages, and the Python version
and packages of the build environment. A third party can use that record to rebuild the wheel and compare the bytes.

It works with every build backend: hatchling, pdm-backend and setuptools through a plugin each, and any other backend,
such as meson-python, maturin or scikit-build-core, through a backend that wraps it.

How these pages are organized
-----------------------------

- :doc:`tutorial` walks you through your first SBOM, from an empty project to a validated wheel.
- The **how-to guides** each solve one task: set python-sbom up for your build backend, describe a wheel built outside
  the standard build interface, describe a zipapp, add what your project knows, render SPDX, or check SBOMs in CI.
- The **reference** lists every option, command and class.
- The **explanation** says how python-sbom is built, what the SBOM records and why, and why each backend gets the
  integration it does.

.. toctree::
   :hidden:

   tutorial

.. toctree::
   :caption: How-to guides
   :hidden:

   how-to/hatchling
   how-to/pdm-backend
   how-to/setuptools
   how-to/other-backends
   how-to/built-elsewhere
   how-to/archive
   how-to/content-provider
   how-to/spdx
   how-to/validate

.. toctree::
   :caption: Reference
   :hidden:

   reference/backends
   reference/configuration
   reference/cli
   reference/api

.. toctree::
   :caption: Explanation
   :hidden:

   explanation/backends
   explanation/document
   explanation/architecture

.. toctree::
   :caption: Project
   :hidden:

   changelog
   contributing
