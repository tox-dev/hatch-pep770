###################
 Check SBOMs in CI
###################

``python-sbom validate`` checks every :term:`CycloneDX` :term:`SBOM` in each :term:`wheel`'s ``.dist-info/sboms`` and in
each :term:`archive` it is given. Install it with the ``validate`` extra, in a tool environment of its own; it says so
when the extra is missing:

.. code-block:: console

    $ pipx install 'python-sbom[validate]'
    $ python-sbom validate dist/

Run it after the build and before the upload, on the files you publish. It fails the job when a wheel has no SBOM, so it
also catches a build that lost the plugin.

****************
 What it checks
****************

Every SBOM gets the CycloneDX 1.6 schema check. For the SBOM python-sbom wrote, it also requires the ``urn:uuid`` serial
number `actions/attest`_ needs to recognize the format, checks that every reference resolves, and validates the
:term:`SPDX` rendering. An SBOM another tool wrote, such as auditwheel_'s ``auditwheel.cdx.json`` or maturin_'s
``<crate>.cyclonedx.json``, gets the schema check alone.

**************************************
 Limit the licenses of bundled wheels
**************************************

Each ``--allow-license`` adds an SPDX id that :term:`bundled wheels <bundled wheel>` may use. With any given, a bundled
wheel whose license the ids do not allow fails the check, and so does one that declares a license only by name:

.. code-block:: console

    $ python-sbom validate dist/ --allow-license MIT --allow-license Apache-2.0

********************
 Check a large SBOM
********************

``validate`` refuses an SBOM with more than 100,000 :term:`components <component>` before it checks anything else, which
bounds what an untrusted SBOM can ask of a :term:`CI` job. Raise the cap for an SBOM you expect to be larger:

.. code-block:: console

    $ python-sbom validate dist/ --max-components 500000

:doc:`/reference/configuration` lists the limits and why they sit where they do.
