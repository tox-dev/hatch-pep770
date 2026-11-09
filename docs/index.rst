#############
 python-sbom
#############

.. raw:: html

    <section class="hero">
      <img class="hero-logo only-light" src="_static/logo-light.svg" alt="">
      <img class="hero-logo only-dark" src="_static/logo-dark.svg" alt="">
      <p class="hero-title">Every wheel you ship,
      <span>with its <abbr title="software bill of materials">SBOM</abbr> inside</span>.</p>
      <p class="hero-tagline">A build plugin that writes a
      <a href="concepts/glossary.html#term-SBOM">software bill of materials (SBOM)</a> in the
      <a href="concepts/glossary.html#term-CycloneDX">CycloneDX</a> format into each
      <a href="concepts/glossary.html#term-wheel">wheel</a> your
      <a href="concepts/glossary.html#term-build-backend">build backend</a> makes, where
      <a href="concepts/glossary.html#term-PEP-770">PEP 770</a> (a Python Enhancement Proposal) tells installers and
      scanners to look for it.</p>
      <div class="hero-actions">
        <a class="primary" href="tutorials/first-sbom.html">Get started</a>
        <a class="secondary" href="how-to/index.html">How-to guides</a>
        <a class="secondary" href="https://github.com/tox-dev/python-sbom">GitHub</a>
      </div>
    </section>

python-sbom writes a :term:`CycloneDX` 1.6 :term:`SBOM` into every :term:`wheel` you build, at
``<name>-<version>.dist-info/sboms/<name>.cdx.json``. That is where :term:`PEP 770` tells installers to keep SBOMs, so
they land in the environment next to the installed package, where scanners look for them.

General-purpose scanners read the dependencies a package declares or the packages an environment has installed. They
cannot see a wheel your project ships as a data file, and they cannot say how the wheel was built. The SBOM python-sbom
writes records both. The :doc:`changelog` lists the changes in each version.

.. grid:: 1 1 2 2
    :gutter: 3

    .. grid-item-card:: Every build backend
        :class-card: feature
        :link: /reference/backends
        :link-type: doc

        A plugin for hatchling_, pdm-backend_ and setuptools_, and a :term:`wrapper backend` for meson-python_,
        maturin_ and the rest.

    .. grid-item-card:: How the wheel was built
        :class-card: feature
        :link: reproducibility
        :link-type: ref

        The source commit, the interpreter and every build tool down to its files, so a third party can rebuild the
        wheel and compare the bytes.

    .. grid-item-card:: What the wheel bundles
        :class-card: feature
        :link: bundled-wheels
        :link-type: ref

        Each wheel a project ships as data, with its hashes, license, files and the packages it vendors.

    .. grid-item-card:: Checked before upload
        :class-card: feature
        :link: /how-to/validate
        :link-type: doc

        ``python-sbom validate`` checks every SBOM against the CycloneDX schema in :term:`CI`, and ``spdx`` renders it
        as :term:`SPDX` 2.3.

A build, the SBOM it wrote, and the check a CI job runs before publishing:

.. code-block:: console

    $ uv build
    Successfully built dist/greet-1.0.tar.gz
    Successfully built dist/greet-1.0-py3-none-any.whl
    $ unzip -Z1 dist/greet-1.0-py3-none-any.whl | grep sboms
    greet-1.0.dist-info/sboms/greet.cdx.json
    $ python-sbom validate dist/ --allow-license MIT
    SBOM in greet-1.0-py3-none-any.whl is valid

*********
 Install
*********

python-sbom runs inside your build, so it goes in ``[build-system] requires`` with the extra for your backend, and a
``[tool.python-sbom]`` table names you as the :term:`supplier`. It needs Python 3.11 or later.

.. tab:: hatchling

    .. literalinclude:: /examples/hatchling/pyproject.toml
        :language: toml
        :caption: pyproject.toml

.. tab:: pdm-backend

    .. literalinclude:: /examples/pdm-backend/pyproject.toml
        :language: toml
        :caption: pyproject.toml

.. tab:: setuptools

    .. literalinclude:: /examples/setuptools/pyproject.toml
        :language: toml
        :caption: pyproject.toml

.. tab:: any other backend

    .. literalinclude:: /examples/meson-python/pyproject.toml
        :language: toml
        :caption: pyproject.toml

Every wheel you build from then on carries the SBOM. :doc:`/how-to/index` covers each backend in detail.

The command line, which describes wheels built elsewhere and checks SBOMs, installs as a tool:

.. tab:: uv

    .. code-block:: bash

        uv tool install 'python-sbom[validate]'
        python-sbom --help

.. tab:: pipx

    .. code-block:: bash

        pipx install 'python-sbom[validate]'
        python-sbom --help

******************
 Where to go next
******************

.. grid:: 1 1 2 2
    :gutter: 3

    .. grid-item-card:: New to python-sbom?
        :class-card: feature
        :link: /tutorials/first-sbom
        :link-type: doc

        The tutorial builds a first package with an SBOM, reads it, and checks it.

    .. grid-item-card:: Have a specific task?
        :class-card: feature
        :link: /how-to/index
        :link-type: doc

        Each guide sets python-sbom up for one backend or handles one kind of artifact.

    .. grid-item-card:: Looking up an option?
        :class-card: feature
        :link: /reference/index
        :link-type: doc

        The backends, the configuration, the command line and the Python :term:`API`.

    .. grid-item-card:: Want to know how it works?
        :class-card: feature
        :link: /concepts/index
        :link-type: doc

        Why each backend gets its integration, what the SBOM records, and how the code is laid out.

.. toctree::
    :hidden:

    Home <self>
    tutorials/index
    how-to/index
    reference/index
    concepts/index
    changelog
    contributing
