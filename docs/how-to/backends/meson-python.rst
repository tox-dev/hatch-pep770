##########################
 Use it with meson-python
##########################

meson-python_ has no plugin interface, so its projects get the :term:`SBOM` through the :term:`wrapper backend`. Make
``python_sbom.backend`` the project's backend, keep meson-python in the build requirements, and name ``mesonpy`` in
``[tool.python-sbom] build-backend``:

.. literalinclude:: /examples/meson-python/pyproject.toml
    :language: toml
    :caption: pyproject.toml

.. literalinclude:: /examples/meson-python/meson.build
    :language: meson
    :caption: meson.build

Then build a :term:`wheel` and check it:

.. literalinclude:: /examples/meson-python/session.console
    :language: console

:example:`meson-python` holds the whole project. :doc:`other-backends` describes what the wrapper does with each
hook.

**************************************
 Pitfall: an sdist outside a checkout
**************************************

meson-python builds an :term:`sdist` with ``meson dist``, which needs a git_ or Mercurial checkout; the wrapper changes
nothing there.

***********************************
 Pitfall: a repair after the build
***********************************

cibuildwheel_ repairs a Linux wheel with auditwheel_, which renames it to its manylinux tag, and a macOS one with
delocate_. Both may copy shared libraries into the wheel, and the SBOM the wrapper wrote names neither those libraries
nor the new file name. Run ``python-sbom embed`` on the repaired wheel, as :ref:`how-to/built-elsewhere:After a repair`
shows with this project.
