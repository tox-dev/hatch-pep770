Load a project's own content provider when the process already imported a module of the same name from another
project, as a test suite building copies of one project does, instead of refusing it. The module cached from elsewhere
is dropped with its submodules, and a provider loaded earlier keeps working.
