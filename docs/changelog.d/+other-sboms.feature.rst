A wheel's SBOM now links to every other SBOM in its ``.dist-info/sboms`` directory, such as maturin's or
auditwheel's, by file name and SHA-256, and ``python-sbom validate`` also checks the ``.cyclonedx.json`` files maturin
writes.
