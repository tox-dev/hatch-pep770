Add the `pep770` hatchling build hook, which writes a CycloneDX 1.6 SBOM into the wheel at
`.dist-info/sboms/<name>.cdx.json`, and the `hatch-pep770 spdx` and `hatch-pep770 validate` commands.
