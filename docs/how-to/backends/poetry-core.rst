#########################
 Use it with poetry-core
#########################

poetry-core_ has no plugin interface, so its projects get the :term:`SBOM` through the :term:`wrapper backend`. Make
``python_sbom.backend`` the project's backend, keep poetry-core in the build requirements, and name
``poetry.core.masonry.api`` in ``[tool.python-sbom] build-backend``:

.. literalinclude:: /examples/poetry-core/pyproject.toml
    :language: toml
    :caption: pyproject.toml

Then build a :term:`wheel` and check it:

.. literalinclude:: /examples/poetry-core/session.console
    :language: console

:example:`poetry-core` holds the whole project. :doc:`other-backends` describes what the wrapper does with each
hook.
