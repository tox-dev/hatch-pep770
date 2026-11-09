#######################
 Use it with flit-core
#######################

flit-core_ has no plugin interface, so its projects get the :term:`SBOM` through the :term:`wrapper backend`. Make
``python_sbom.backend`` the project's backend, keep flit-core in the build requirements, and name ``flit_core.buildapi``
in ``[tool.python-sbom] build-backend``:

.. literalinclude:: /examples/flit-core/pyproject.toml
    :language: toml
    :caption: pyproject.toml

Then build a :term:`wheel` and check it:

.. literalinclude:: /examples/flit-core/session.console
    :language: console

:example:`flit-core` holds the whole project. :doc:`other-backends` describes what the wrapper does with each
hook.
