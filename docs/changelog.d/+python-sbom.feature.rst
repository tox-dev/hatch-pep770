Add the ``python-sbom`` hatchling build hook, which writes a CycloneDX 1.6 SBOM into each wheel, the Python API behind
it, and the ``python-sbom`` command: ``embed`` writes the same SBOM into wheels other build backends build, ``archive``
describes another zip archive a project publishes, such as a zipapp, and with ``--embed`` adds that SBOM to it,
deflated, ``spdx`` renders an SBOM as SPDX, and ``validate`` checks the SBOMs in wheels and archives against the
official CycloneDX schema files python-sbom ships, with jsonschema-rs, and rejects one listing more than 100,000
components unless ``--max-components`` allows more.
