#include "Python.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/callback.h>


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


static PyObject *decode (PyObject* self, PyObject *args)
{
  CAMLlocal1(ml_res);
  static value *decode_func;
  void *src;
  value *dst;
  int len;
  char *offset;
  char *entry;
  
  if (!PyArg_ParseTuple(args, "s#ss", &src, &len, &offset, &entry))
    return NULL;
  if (!load_caml(&decode_func, "decode"))
    return NULL;
  dst = caml_alloc_string(len);
  memcpy(String_val(dst), src, len);
  if ( dst == NULL )
    return NULL;
  ml_res = caml_callback3 (*decode_func, dst, caml_copy_string(offset), caml_copy_string(entry));
  return Py_BuildValue("O", ml_res);
}



static PyObject *process_elf(PyObject *self, PyObject *args)
{
  static value *process_func;
  int flat;
  int *segments;
  value *seg_array;
  void *src;
  value *dst;
  int len;
  char *offset;
  char *entry;
  value args[6];
  int addr_sz;

  if (!PyArg_ParseTuple(args, "i(iiiiiii)s#ss", &flat, &segments, &addr_sz, &src, &len, &offset, &entry))
    return NULL;
  if (!load_caml(&process_func, "process_elf"))
    return NULL;
  dst = caml_alloc_string(len);
  memcpy(String_val(dst), src, len);
  seg_array = caml_alloc_array(Int_val, segments);
  args[0] = Int_val(flat);
  args[1] = seg_array;
  args[2] = Int_val(addr_sz);
  args[3] = dst; 
  args[4] = caml_copy_string(offset);
  args[5] = caml_copy_string(entry);
  caml_callbackN(*process_func, 6, args);
  return Py_None;
}

static PyObject *process_pe(PyObject *self, PyObject *args)
{
  static value *process_func;
  int flat;
  int *segments;
  value *seg_array;
  void *src;
  value *dst;
  int len;
  char *offset;
  char *entry;
  value args[8];
  int addr_sz, op_sz, stack_width

    if (!PyArg_ParseTuple(args, "i(iiiiii)s#ss", &flat, &segments, &addr_sz, &op_sz, &stack_width, &src, &len, &offset, &entry))
    return NULL;
  if (!load_caml(&process_func, "process_elf"))
    return NULL;
  dst = caml_alloc_string(len);
  memcpy(String_val(dst), src, len);
  seg_array = caml_alloc_array(Int_val, segments);
  args[0] = Int_val(flat);
  args[1] = seg_array;
  args[2] = Int_val(addr_sz);
  args[3] = Int_val(op_sz);
  args[4] = Int_val(stack_width);
  args[5] = dst; 
  args[6] = caml_copy_string(offset);
  args[7] = caml_copy_string(entry);
  caml_callbackN(*process_func, 8, args);
  return Py_None;
}


static PyMethodDef MlMethods[] = {
  { "process_elf", load_elf_x86, METH_VARARGS, "Call Main.process_elf" },
  { "process_pe", load_pe_x86, METH_VARARGS, "Call Main.process_pe" }
	{NULL, NULL, 0, NULL}
};
 
PyMODINIT_FUNC
initcaml(void)
{
	char *argv[2];	
	argv[0]="";
	argv[1]=NULL;
	caml_startup(argv);
	(void) Py_InitModule("caml", MlMethods);
}

