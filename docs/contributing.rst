Contributing
============

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
