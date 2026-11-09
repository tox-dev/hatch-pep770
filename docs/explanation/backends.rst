Why each backend gets its integration
=====================================

The SBOM describes the finished wheel: its file name, its files with their hashes, and the environment that built it.
So it has to be written after the backend has written the wheel, inside the build, and every integration is shaped by
where a backend lets code run at that moment.

Plugins where a backend has a hook after the build
--------------------------------------------------

Three backends let a plugin run once the artifact exists:

- hatchling calls a build hook's ``finalize`` with the wheel's path;
- `pdm-backend <https://backend.pdm-project.org/hooks/>`_ calls ``pdm_build_finalize`` with the artifact's path;
- `setuptools <https://setuptools.pypa.io/en/latest/userguide/extension.html>`_ lets a plugin replace the commands it
  runs, so python-sbom wraps ``bdist_wheel`` and ``sdist``.

A plugin keeps the project's ``build-backend`` as it is and sees the artifact the backend built. hatchling enables a
hook by its table. pdm-backend and setuptools run every plugin installed in the build environment, so python-sbom acts
only for a project with a ``[tool.python-sbom]`` table, and a package that merely has python-sbom installed nearby
builds as before.

A wrapper where a backend has none
----------------------------------

meson-python, maturin, flit-core and uv_build have no plugin interface. poetry-core's build script runs before
packaging, and scikit-build-core has none that runs after the build either; its own documentation recommends `wrapping
the backend <https://scikit-build-core.readthedocs.io/en/latest/configuration/wrapping.html>`_. Static SBOM options, such
as hatchling's ``sbom-files`` or maturin's include list, add a file while the wheel is still being written, too early
for a document that lists the wheel's own hashes.

Every backend shares one interface, though: the hooks of `PEP 517 <https://peps.python.org/pep-0517/>`_ and `PEP 660
<https://peps.python.org/pep-0660/>`_. ``python_sbom.backend`` implements it by handing each call to the backend the
project names, then writing the SBOM into the wheel it returned. It needs no code per backend, so a backend released
later works with it too. It runs in the isolated environment the frontend made for the build, so the SBOM lists the
build tools that ran.

The wrapper exposes an optional hook only when the wrapped backend has it. A frontend checks for an optional hook, such
as ``prepare_metadata_for_build_wheel``, and falls back to its own default when it is missing; a wrapper that defined
every hook would change what the frontend does.

The sdist
---------

A wheel built from an sdist, which is what ``python -m build`` and ``uv build`` do by default, is built outside the git
checkout, so it cannot ask git for its commit. Each integration therefore adds ``.python-sbom-revision``, holding the
commit, to the sdist of a clean checkout. The plugins add it while the backend writes the sdist; the wrapper adds it to
the finished archive, keeping the backend's own times so a reproducible sdist stays reproducible.

What still runs after the build
-------------------------------

Two things sit outside every backend:

- Tools that build without the build interface, such as ``maturin build`` in maturin-action, never call a plugin or the
  wrapper.
- ``auditwheel repair`` and ``delocate`` run after the build and rename the wheel, so a document written during the
  build names a file that is never published.

``python-sbom embed`` covers both: it describes a finished wheel from the outside. It cannot see the build environment,
so it records the one it runs in, or the one ``--build-env`` names; :doc:`../how-to/built-elsewhere` shows how to make
that the real one.
