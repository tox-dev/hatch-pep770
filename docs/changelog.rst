Changelog
=========

.. towncrier release notes start

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
