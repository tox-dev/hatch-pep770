Changelog
=========

.. towncrier release notes start

.. _release-0-3-0:

0.3.0 (2026-11-09)
------------------

.. _release-0-3-0-added:

Added
~~~~~

- A wheel's SBOM now links to every other file in its ``.dist-info/sboms`` directory, such as maturin's or auditwheel's,
  by file name and SHA-256, and ``python-sbom validate`` also checks the ``.cyclonedx.json`` files maturin writes
  (:pr:`8`) by :user:`gaborbernat`.

.. _release-0-3-0-documentation:

Documentation
~~~~~~~~~~~~~

- Give each build backend its own how-to page, under a new backends section, built around an example project whose build
  and check the test suite runs, and add one for maturin projects: what maturin's SBOM and python-sbom's each hold, and
  how to add python-sbom's when a build frontend, ``maturin build`` or maturin-action builds the wheel (:pr:`8`) by
  :user:`gaborbernat`.

.. _release-0-2-0:

0.2.0 (2026-11-09)
------------------

.. _release-0-2-0-added:

Added
~~~~~

- Write the SBOM with any build backend: a pdm-backend hook and a setuptools plugin act for every project with a
  ``[tool.python-sbom]`` table, and ``python_sbom.backend`` wraps any other backend, such as meson-python or maturin,
  named by the new ``build-backend`` option. Each records the source revision in the sdist, as the hatchling hook does
  (:pr:`7`) by :user:`gaborbernat`.

.. _release-0-1-2:

0.1.2 (2026-11-08)
------------------

.. _release-0-1-2-fixed:

Fixed
~~~~~

- Load a project's own content provider when the process already imported a module of the same name from another
  project, as a test suite building copies of one project does, instead of refusing it. The module cached from elsewhere
  is dropped with its submodules, and a provider loaded earlier keeps working (:pr:`5`) by :user:`gaborbernat`.

.. _release-0-1-1:

0.1.1 (2026-11-08)
------------------

.. _release-0-1-1-packaging:

Packaging
~~~~~~~~~

- First release on PyPI. The 0.1.0 tag was never published: its release build lacked hashes for the packages
  python-sbom's own build hook needs, so 0.1.1 is the first release and carries everything listed under 0.1.0 (:pr:`4`)
  by :user:`gaborbernat`.

.. _release-0-1-0:

0.1.0 (2026-11-08)
------------------

.. _release-0-1-0-added:

Added
~~~~~

- Add the ``python-sbom`` hatchling build hook, which writes a CycloneDX 1.6 SBOM into each wheel, the Python API behind
  it, and the ``python-sbom`` command: ``embed`` writes the same SBOM into wheels other build backends build,
  ``archive`` describes another zip archive a project publishes, such as a zipapp, and with ``--embed`` adds that SBOM
  to it, deflated, ``spdx`` renders an SBOM as SPDX, and ``validate`` checks the SBOMs in wheels and archives against
  the official CycloneDX schema files python-sbom ships, with jsonschema-rs, and rejects one listing more than 100,000
  components unless ``--max-components`` allows more (:pr:`2`) by :user:`gaborbernat`.
