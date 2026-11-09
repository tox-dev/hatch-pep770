######################
 Use it with uv-build
######################

uv_build_ has no plugin interface, so its projects get the :term:`SBOM` through the :term:`wrapper backend`. Make
``python_sbom.backend`` the project's backend, keep uv-build in the build requirements, and name ``uv_build`` in
``[tool.python-sbom] build-backend``:

.. literalinclude:: /examples/uv-build/pyproject.toml
    :language: toml
    :caption: pyproject.toml

Then build a :term:`wheel` and check it:

.. literalinclude:: /examples/uv-build/session.console
    :language: console

:example:`uv-build` holds the whole project. :doc:`other-backends` describes what the wrapper does with each
hook.

******************************************
 Pitfall: ``uv build`` without the wrapper
******************************************

``uv build`` builds a uv_build project in its own process when ``uv_build`` is the backend, so no build hook runs. With
the wrapper as the backend, uv calls the build interface, and the wrapper runs.
