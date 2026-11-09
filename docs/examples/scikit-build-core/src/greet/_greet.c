#include <Python.h>

static PyObject *hello(PyObject *self, PyObject *args) { return PyUnicode_FromString("hello"); }

static PyMethodDef methods[] = {{"hello", hello, METH_NOARGS, NULL}, {NULL, NULL, 0, NULL}};

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_greet", NULL, -1, methods};

PyMODINIT_FUNC PyInit__greet(void) { return PyModule_Create(&module); }
