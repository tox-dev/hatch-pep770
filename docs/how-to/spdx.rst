Render an SBOM as SPDX
======================

Some tools read only `SPDX <https://spdx.dev/>`_. ``python-sbom spdx`` renders the CycloneDX document as SPDX 2.3 JSON.
It needs no extra:

.. code-block:: console

    $ unzip -p dist/project-1.0-py3-none-any.whl '*/sboms/project.cdx.json' > project.cdx.json
    $ python-sbom spdx project.cdx.json project.spdx.json

The SPDX document keeps the packages, their hashes, licenses and purls, and the containment, dependency and build tool
relationships. Its namespace ends in the CycloneDX serial number, so both documents name the same build.

It leaves out two things SPDX 2.3 cannot hold: the per-file hashes, because SPDX 2.3 wants a SHA-1 for every file and
wheel ``RECORD`` files hold SHA-256, and the build record. Keep the CycloneDX document when you need those.

The command checks only the fields the rendering reads. To check the whole document, run ``python-sbom validate``, which
also validates the SPDX rendering; see :doc:`validate`.
