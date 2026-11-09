######################################
 Describe a zipapp or another archive
######################################

A project may also publish a zipapp, such as virtualenv's ``virtualenv.pyz``, which holds virtualenv's own
``.dist-info`` at its top level, the wheels it seeds, and its dependencies unpacked under ``__virtualenv__/``.
``python-sbom archive`` describes such an archive the way the hook describes a wheel: the archive's own files, the
project's distribution, each wheel it bundles as a ``.whl`` member, and each one unpacked into a directory with a
``.dist-info``. The content provider the option names hears of every bundled wheel, and its context reads the archive's
files:

.. code-block:: console

    $ python-sbom archive virtualenv.pyz --build-script tasks/make_zipapp.py --embed
    wrote virtualenv.pyz.cdx.json
    wrote virtualenv.pyz.cdx.json into virtualenv.pyz

The document takes its options, source revision and toolchain the way the wheel's does, so both name the project alike.
Its build time comes from ``SOURCE_DATE_EPOCH``, or the current time without it; set ``SOURCE_DATE_EPOCH`` for both
builds to give them one time. ``--embed`` adds the document to the archive's top level, where ``python-sbom validate
virtualenv.pyz`` finds it. It goes in deflated at level 9 whatever the archive's other members use, since a zipapp may
store them all and the SBOM, megabytes of JSON, would then add its full size. The entry carries a fixed time and Unix
attributes and the other members keep their bytes, so adding it to one archive gives the same bytes on every system with
the same zlib.
