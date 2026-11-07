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
