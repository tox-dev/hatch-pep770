#############
 python-sbom
#############

python-sbom writes a `CycloneDX <https://cyclonedx.org/>`_ 1.6 SBOM into every wheel you build, at
``<name>-<version>.dist-info/sboms/<name>.cdx.json``. That is where `PEP 770 <https://peps.python.org/pep-0770/>`_ tells
installers to keep SBOMs, so they land in the environment next to the installed package, where scanners look for them:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatchling>=1.28', 'python-sbom[hatch]>=0.2']

    [tool.hatch.build.hooks.python-sbom]

General-purpose scanners read the dependencies a package declares or the packages an environment has installed. They
cannot see a wheel your project ships as a data file, and they cannot say how the wheel was built. The SBOM python-sbom
writes records both: the wheels you bundle, with their hashes, licenses and vendored packages, and the Python version
and packages of the build environment. A third party can use that record to rebuild the wheel and compare the bytes. The
:doc:`changelog` lists the changes in each version.

**************
 Installation
**************

python-sbom runs inside your build, so it goes in ``[build-system] requires``, with the extra for your backend, rather
than into an environment of yours. It needs Python 3.11 or later. :doc:`/reference/backends` names the extra for each
backend; the command line, for wheels built elsewhere and for checking SBOMs, installs as a tool:

.. code-block:: bash

    pipx install 'python-sbom[validate]'

*******************
 Learn python-sbom
*******************

.. grid:: 1 2 2 2
    :gutter: 2

    .. grid-item-card::

        **New to python-sbom?**

        The :doc:`/tutorials/index` build a first package with an SBOM, read it, and check it.

    .. grid-item-card::

        **Have a specific task?**

        Each of the :doc:`/how-to/index` sets python-sbom up for one backend or handles one kind of artifact.

    .. grid-item-card::

        **Looking up an option?**

        The :doc:`/reference/index` lists the backends, the configuration, the command line and the Python API.

    .. grid-item-card::

        **Want to know how it works?**

        :doc:`/concepts/index` says why each backend gets its integration, what the SBOM records, and how the code is
        laid out.

**********
 Features
**********

.. grid:: 1 2 2 3
    :gutter: 2

    .. grid-item-card::
        **Every build backend**

        A plugin for hatchling, pdm-backend and setuptools, and a wrapper backend for the rest.

        - :doc:`/how-to/hatchling`
        - :doc:`/how-to/pdm-backend`
        - :doc:`/how-to/setuptools`
        - :doc:`/how-to/other-backends`

    .. grid-item-card::
        **Wheels built elsewhere**

        Describe a wheel after ``maturin build``, ``auditwheel repair`` or ``delocate``.

        - :doc:`/how-to/built-elsewhere`

    .. grid-item-card::
        **Bundled wheels**

        Each wheel a project ships as data gets its hashes, license, files and vendored packages.

        - :ref:`bundled-wheels`
        - :doc:`/how-to/content-provider`

    .. grid-item-card::
        **Reproducible builds**

        The source revision and the build tools, down to their files, so a third party can rebuild the wheel.

        - :ref:`reproducibility`
        - :ref:`source-revision`

    .. grid-item-card::
        **Zipapps and other archives**

        The same SBOM for a ``.pyz`` or another zip the project publishes.

        - :doc:`/how-to/archive`

    .. grid-item-card::
        **Checks and SPDX**

        Validate SBOMs in CI against the CycloneDX schema, and render them as SPDX 2.3.

        - :doc:`/how-to/validate`
        - :doc:`/how-to/spdx`

.. toctree::
    :hidden:

    self
    tutorials/index
    how-to/index
    reference/index
    concepts/index
    changelog
    contributing
