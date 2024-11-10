dump-heap
=========

Dumps the heap of a running Python program.

This whole process is roughly equivalent to running the following C pseudocode
in the target running Python program (using the same tricks that gdb use to run
`call`), only stopping the program enough to run this code:

```c
void *payload_addr = mmap(
  NULL,
  PAGE_SIZE,
  PROT_READ|PROT_WRITE|PROT_EXEC,
  MAP_PRIVATE|MAP_ANONYMOUS,
  -1 // fd,
  0 // address
);
if (payload_addr == MAP_FAILED) {
  return -1;
}
memcpy(payload_addr, RUN_PYTHON_PAYLOAD, sizeof(RUN_PYTHON_PAYLOAD));
typedef int (*)(
  typeof(fopen),
  typeof(fclose),
  typeof(PyGILState_Ensure),
  typeof(PyGILState_Release),
  typeof(PyRun_SimpleFile)
) run_python;
int ret = ((run_python)payload_addr)(
  fopen,
  fclose,
  PyGILState_Ensure,
  PyGILState_Release,
  PyRun_SimpleFile
);
munmap(payload_addr, PAGE_SIZE);
return ret;
```

Once that code is run, it will wait for a file to exist in the filesystem which
contains the result of the operation.

Inspired by the following tools:

* https://github.com/lmacken/pyrasite
* https://github.com/robusta-dev/debug-toolkit
* https://ancat.github.io/python/2019/01/01/python-ptrace.html
