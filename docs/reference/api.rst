############
 Python API
############

The Python :term:`API` is what a :term:`build backend` loads and what a project needs to add its own knowledge to the
:term:`SBOM`: the backend integrations and the content provider they call, with the types those take and return.
Everything else, from embedding to :term:`validation`, runs through the :doc:`/reference/cli`. The core is importable
from ``python_sbom`` without any build backend; each integration lives in a module of its own and imports only its
backend.

.. py:data:: python_sbom.__version__
    :type: str

    The installed version of python-sbom.

**********************
 Backend integrations
**********************

.. autoclass:: python_sbom.hatch.SbomBuildHook
    :members: content_provider

.. autoclass:: python_sbom.pdm.SbomBuildHook
    :members: pdm_build_hook_enabled, pdm_build_initialize, pdm_build_update_files, pdm_build_finalize

.. autofunction:: python_sbom.setuptools.finalize_distribution_options

.. autofunction:: python_sbom.backend.build_wheel

.. autofunction:: python_sbom.backend.build_sdist

******************
 Content provider
******************

.. autoclass:: python_sbom.ContentProvider
    :members: bundled_wheel, contributions

.. autoclass:: python_sbom.ProviderContext
    :members: read

.. autoclass:: python_sbom.BundledWheelInfo

.. autoclass:: python_sbom.Contributions

.. autoclass:: python_sbom.Settings

.. autoclass:: python_sbom.ProjectIdentity

*****************
 Component types
*****************

These :class:`~typing.TypedDict` types describe the :term:`JSON` a provider builds. Each follows the :term:`CycloneDX`
1.6 object of the same name; the `CycloneDX 1.6 reference <https://cyclonedx.org/docs/1.6/json/#components>`_ describes
every key.

.. py:class:: python_sbom.Component

    A CycloneDX 1.6 :term:`component`, a distribution, an application, the interpreter or a file, as a dictionary with
    the keys the CycloneDX component object defines. python-sbom uses ``type``, ``bom-ref``, ``name``, ``version``, ``purl``,
    ``supplier`` (an :class:`~python_sbom.OrganizationalEntity`), ``authors`` (:class:`~python_sbom.Contact`),
    ``description``, ``licenses`` (:class:`~python_sbom.License`), ``copyright``, ``hashes``
    (:class:`~python_sbom.Hash`), ``externalReferences`` (:class:`~python_sbom.ExternalReference`), ``properties``
    (:class:`~python_sbom.Property`), ``evidence`` (:class:`~python_sbom.Evidence`) and the nested ``components``.

.. autoclass:: python_sbom.Property
    :no-members:

.. autoclass:: python_sbom.Dependency
    :no-members:

.. autoclass:: python_sbom.OrganizationalEntity
    :no-members:

.. autoclass:: python_sbom.Contact
    :no-members:

.. autoclass:: python_sbom.ExternalReference
    :no-members:

.. autoclass:: python_sbom.Hash
    :no-members:

.. autoclass:: python_sbom.License
    :no-members:

.. autoclass:: python_sbom.LicenseInfo
    :no-members:

.. autoclass:: python_sbom.Evidence
    :no-members:

.. autoclass:: python_sbom.Identity
    :no-members:

.. autoclass:: python_sbom.IdentityMethod
    :no-members:

********
 Errors
********

.. autoexception:: python_sbom.SbomError

.. autoexception:: python_sbom.MissingExtraError
