``python-sbom validate`` checks the CycloneDX schema with jsonschema-rs, against the official CycloneDX schema files
python-sbom now ships, so an SBOM validates in milliseconds instead of seconds, and its time grows in step with its
size; the default ``--max-components`` cap rises from 5,000 to 100,000 components to match. Building an SBOM reads each
build-environment distribution's ``RECORD`` and metadata once, and rewriting the wheel copies its other members without
recompressing them.
