###############################
 Use it with scikit-build-core
###############################

scikit-build-core_ has no plugin interface, so its projects get the :term:`SBOM` through the :term:`wrapper backend`.
Make ``python_sbom.backend`` the project's backend, keep scikit-build-core in the build requirements, and name
``scikit_build_core.build`` in ``[tool.python-sbom] build-backend``:

.. literalinclude:: /examples/scikit-build-core/pyproject.toml
    :language: toml
    :caption: pyproject.toml

.. literalinclude:: /examples/scikit-build-core/CMakeLists.txt
    :language: cmake
    :caption: CMakeLists.txt

Then build a :term:`wheel` and check it:

.. literalinclude:: /examples/scikit-build-core/session.console
    :language: console

:example:`scikit-build-core` holds the whole project. :doc:`other-backends` describes what the wrapper does with each
hook.

************************************
 Projects that build with hatchling
************************************

A project built with hatchling_ and scikit-build-core's hatch plugin uses :doc:`hatchling` instead: the
python-sbom hook runs next to scikit-build-core's.
