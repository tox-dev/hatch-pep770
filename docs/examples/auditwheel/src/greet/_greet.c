#include <Python.h>

/* from libuuid, which no manylinux policy allows a wheel to expect, so auditwheel copies it into the wheel */
void uuid_generate(unsigned char out[16]);

static PyObject *hello(PyObject *self, PyObject *args) {
    unsigned char id[16];
    uuid_generate(id);
    return PyUnicode_FromFormat("hello %02x%02x", id[0], id[1]);
}

static PyMethodDef methods[] = {{"hello", hello, METH_NOARGS, NULL}, {NULL, NULL, 0, NULL}};

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_greet", NULL, -1, methods};

PyMODINIT_FUNC PyInit__greet(void) { return PyModule_Create(&module); }
