Contributing
============

How the code fits together
--------------------------

Each artifact has one pipeline in ``_generate``, and the two read alike. An adapter, a backend integration or a command
of the command line, gathers the options, the content provider, the build scripts and the build facts (time, source
revision and toolchain). The pipeline opens the artifact once, reads it into a tree (``_collect/_wheel.py`` or
``_collect/_archive.py``), maps the tree to an ``Artifact`` with a pure function (``_model/_wheel.py`` or
``_model/_archive.py``), and hands that to ``_model/_bom.py``, which adds what every artifact of the project shares.
:ref:`concepts:Architecture` draws the packages and their imports.

To record a new field, read it at the edge into ``_model/_inputs.py`` and write it in ``_model``; to add a subcommand,
write a ``run`` function in a new ``_cli/_<command>.py`` and register its arguments and the
``"python_sbom._cli._<command>:run"`` handler in ``_cli/_parser.py``, which loads the module only when the command runs.
Tests mirror the source: ``tests/<package>/test_<module>.py``.

What each layer guarantees
--------------------------

A change is easiest to review against the guarantee of the layer it touches, and the test named here is the one that
fails when that guarantee breaks. Each test crosses a boundary on purpose: unit tests of one layer did not catch the
mismatches between layers these guard against.

- ``_wheel`` reads an artifact through one open handle per build, checked once for clashing member names, and never
  trusts a member's stated size. The bytes it hands on are the bytes the artifact ships.
  ``tests/_wheel/test_reader.py``, and ``test_embed_rewrites_record_by_parsed_path`` for rewriting RECORD.
- ``_collect`` turns the project and the artifact into inputs. Source configuration only selects: a bundled wheel is
  described from the artifact's copy, matched by digest, and a selected wheel the artifact does not ship is refused. A
  provider module another project already imported in the same process is refused rather than reused.
  ``test_bundled_wheel_not_shipped_is_refused``, ``test_provider_of_another_project_is_not_reused``.
- ``_model`` builds documents with pure functions. ``_model/_graph.py`` defines the sets every layer judges alike:
  ``artifact_contents`` is what the artifact holds or declares wherever the document nests it, ``shipped_libraries`` is
  what it carries bytes for, and ``reference_problems`` is the one check of repeated and unknown references that
  generation refuses and validation reports. ``test_archive_bundled_wheel_judged_wherever_it_sits``.
- ``_validate`` reads hostile input: bounded size, depth and component count before the schema runs, then references,
  the SPDX rendering and the license policy over ``artifact_contents``.
  ``test_repeated_dependency_entry_cannot_hide_an_invalid_one``.
- ``_formats`` renders without losing identity: every SPDX id is unique because it ends in the full digest of its
  ``bom-ref``. ``test_spdx_ids_of_refs_differing_in_dropped_characters_stay_distinct``.
- ``_generate`` orders reading, building and writing: an artifact stays open while its document is built, is closed
  before it is rewritten, and is never overwritten by its own SBOM. ``test_archive_refuses_output_over_archive``, in
  ``tests/_cli`` since the command line is where an output path reaches it.

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
