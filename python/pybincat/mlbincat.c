#include "Python.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/callback.h>
#include <caml/printexc.h>
#include <caml/compatibility.h>

static PyObject *OcamlException;

static int load_caml(value **func, char *funcname)
{
	if (*func == NULL) {
		*func = caml_named_value (funcname) ;
		if (*func == NULL) {
			PyErr_SetString(PyExc_NameError, funcname);
			return 0;
		}
	}
	return 1;
}


static PyObject *process(PyObject *self, PyObject *args)
{
  static value *process_func;

  char *configfile;
  char *resultfile;
  char *logfile;

  if (!PyArg_ParseTuple(args, "sss", &configfile, &resultfile, &logfile))
    return NULL;
  if (!load_caml(&process_func, "process"))
    return NULL;

  value res;

  res = caml_callback3_exn(*process_func, caml_copy_string(configfile), caml_copy_string(resultfile), caml_copy_string(logfile));
  if (Is_exception_result(res)) {
    value exn = Extract_exception(res);
	PyErr_SetString(OcamlException, (*caml_format_exception)(exn));
	return NULL;
  }
  return Py_None;
}


static PyMethodDef MlMethods[] = {
  { "process", process, METH_VARARGS, "Launch the analyzer" },
  {NULL, NULL, 0, NULL}
};
static struct PyModuleDef cMLBincat =
{
    PyModuleDef_HEAD_INIT,
    "mlbincat",
    "",          /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    MlMethods
};

PyMODINIT_FUNC PyInit_mlbincat(void)
{
	char *argv[2];
	argv[0]="";
	argv[1]=NULL;
	caml_startup(argv);
	PyObject *module;
	module = PyModule_Create(&cMLBincat);
	if (module == NULL)
	  return NULL;

	OcamlException = PyErr_NewException("mlbincat.OcamlException", NULL, NULL);
	Py_INCREF(OcamlException);
	PyModule_AddObject(module, "error", OcamlException);
    return module;
}

