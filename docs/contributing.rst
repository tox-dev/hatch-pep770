Contributing
============

How the code fits together
--------------------------

Every SBOM comes out of one pipeline. An adapter, the hatchling hook or a command of the command line, gathers what the
edge knows: the request (the wheel's core metadata and file name, the project directory, the options and the build
scripts), the source tree (license files and bundled wheels), and the build facts (time, source revision and toolchain).
It hands them, with a content provider, to the pipeline, which builds the document with pure functions in ``_model``.
:doc:`explanation` draws the packages and their imports.

To record a new field, read it at the edge into ``_model/_inputs.py`` and write it in ``_model``; to add a subcommand,
add a registration function and a handler next to the others in ``_cli/_commands.py`` and list the registration in
``_cli/_parser.py``. Tests mirror the source: ``tests/<package>/test_<module>.py``.

Updating the schemas
--------------------

``python-sbom validate`` checks documents against the official CycloneDX schema files, which ship byte for byte under
``src/python_sbom/_validate/schemas``. Each comes from a tag of `CycloneDX/specification
<https://github.com/CycloneDX/specification>`_: ``bom-1.6.schema.json`` and the ``jsf-0.82.schema.json`` it references
from ``1.6.2``, and ``spdx.schema.json`` and the Apache-2.0 ``LICENSE`` from ``1.7.2``, the newest, since the
cyclonedx.org URL every schema version references serves the newest license list. These commands fetch the shipped files
from their raw URLs; change the tag to take a newer release:

.. code-block:: console

    $ cd src/python_sbom/_validate/schemas
    $ curl -fsSLO https://raw.githubusercontent.com/CycloneDX/specification/1.6.2/schema/bom-1.6.schema.json
    $ curl -fsSLO https://raw.githubusercontent.com/CycloneDX/specification/1.6.2/schema/jsf-0.82.schema.json
    $ curl -fsSLO https://raw.githubusercontent.com/CycloneDX/specification/1.7.2/schema/spdx.schema.json
    $ curl -fsSLO https://raw.githubusercontent.com/CycloneDX/specification/1.7.2/LICENSE
    $ sha256sum *

Put each file's tag and SHA-256 into the cases of ``test_schema_files_are_the_upstream_release`` in
``tests/_validate/test_schemas.py``, which fails when a shipped file is not the release it names. ``.gitattributes``
marks the directory ``-text`` and ``.pre-commit-config.yaml`` excludes it, so neither git nor the hooks rewrite the
files' line endings, whitespace or formatting.

Benchmarks
----------

``bench/`` times python-sbom's hot paths with `pyperf <https://pyperf.readthedocs.io/>`_; CI does not run it. The
``bench`` tox environment passes its arguments to ``python -m bench``:

.. code-block:: console

    $ tox r -e bench -- prepare
    $ tox r -e bench -- run
    $ tox r -e bench -- compare ../baseline/.tox/bench-results/cpython3.15 .tox/bench-results/cpython3.15

``prepare`` builds the fixtures, the only step that needs the network. ``run`` times each case in its own pyperf process
tree and writes one JSON file per case under ``.tox/bench-results/<python>/``; options after a second ``--`` reach
pyperf. ``profile`` runs each case once under cProfile, and under py-spy with ``--py-spy``. Both take case names to run
only those, and ``list`` prints the names. ``report`` renders result files as a Markdown table, and ``compare`` puts two
result directories side by side. The timed process imports the python-sbom its environment installed, so to compare two
revisions, run the cases from a checkout of each and compare their result directories.

Changelog fragments
-------------------

Add a changelog fragment under ``docs/changelog.d`` when a pull request changes what package users can use or observe.
Name it ``+short-name.<type>.rst``, for example ``+vendored-licenses.feature.rst``. The name describes the change; you
do not need a pull request number before opening the pull request. Write one change per fragment, and use several
fragments when a pull request has several user-visible changes.

Choose the type by its effect on users:

- ``feature`` (Added): a new capability, including adding or removing support for a Python version.
- ``change`` (Changes): a change in behavior that remains available.
- ``bugfix`` (Fixed): a correction to existing behavior.
- ``doc`` (Documentation): a documentation change users need to know about.
- ``breaking`` (Breaking changes): a change that requires users to change their usage.
- ``security`` (Security): a security fix users need to act on.
- ``performance`` (Performance): a visible speed or resource improvement.
- ``deprecation`` (Deprecated): a supported behavior scheduled for removal.
- ``removal`` (Removed): removal of a user-facing capability.
- ``packaging`` (Packaging): a change to installation or distributions.

Apply the ``skip news`` label to a pull request with no user-visible change. You can add the label after opening the
pull request. Supplied fragments are still checked when the label is present. Bot pull requests need no fragment unless
they include one.

The release workflow links each fragment to its merged pull request and credits its human author. If several people
authored a change, put their `GitHub <https://github.com/>`_ handles in a ``by`` credit in the fragment; omit bots and
reviewers. The changelog uses linked names, while ``GitHub`` Release notes use ``@handle``.

Build the documentation with ``tox r -e docs``; ``tox r -e docs -- -b linkcheck`` checks its external links.
