dump-heap
=========

Dumps the whole heap of a running Python program (x86_64 Linux only), including
references between objects and small snippets of contents to aid in debugging
memory leaks in Python processes.

So you suspect you have a leak...
=================================

First, try using something like [memray](https://bloomberg.github.io/memray/)
to interactively inspect your application, which is going to be a lot easier
and there's enough material online to start from. This instruments allocations
and frees, so you'll know where the memory was allocated. That is sufficient in
most cases, since you can most likely trace the leak. _However_, sometimes this
is not sufficient: if there's something accidentally keeping a reference alive.
Cursed examples we have seen are leaked
[`asyncio.Task`](https://docs.python.org/3/library/asyncio-task.html#asyncio.Task)
and dangling async generators.

With this tool, you can take three heap snapshots at different points in time
and analyze the objects among them that are likely to be leaked.

To take a snapshot, run these commands in the same machine / container as the
target process:

```shell
~$ curl -sSL https://github.com/lhchavez/dump-heap/releases/download/v0.1.0/dump-heap -o dump-heap
~$ chmod +x dump-heap
~$ sudo ./dump-heap \
    --output=/tmp/heap.bin \
    $(pidof python) && \
  gzip /tmp/heap.bin
```

Save the heap somewhere, wait several minutes / hours, and run it again. Then
wait several minutes / hours and run it a third time. The first snapshot will
serve as a baseline of all long-lived objects that are expected to be present
in all snapshots (and therefore should be excluded from leak analysis). The
second snapshot will be the one we want to analyze for leaks, and the third one
will serve to analyze what objects have survived (and therefore should be
included in the leak analysis). In set notation, potentially leaked objects are
those present in $`(S_2 \cap S_3) \setminus S_1`$.

To get the largest potentially leaked objects among snapshots:

```shell
~/debug-heap$ uv run analyze_heap.py \
    --remove-heap-dump ~/heap.1.bin.gz \
    --intersect-heap-dump ~/heap.3.bin.gz \
    top \
    --top-allocations=1000 \
    ~/heap.2.bin.gz
```

You can add the `--show-parents` flag to identify what's holding a (transitive)
reference to the potentially-leaked object, but that is very noisy. If you want
to visualize that in a nice [Graphviz](https://graphviz.org/)-produced svg, you
can grab the address of an object you want to focus on (say,
`0x00005d4bbffe2100`), a few objects you want to exclude (because they have
just too many references, `!0x7967b8ed0fe0,!0x7967eff3ad80,!0x7967e7cca000`,
for example), and specify an optional type to highlight (`asyncio.Task` is
useful in async contexts, since task leaks are surprising and often contribute
a lot):

```shell
~/debug-heap$ uv run analyze_heap.py \
    graph \
    --filter='0x00005d4bbffe2100,!0x7967b8ed0fe0,!0x7967eff3ad80,!0x7967e7cca000' \
    --highlight='asyncio.Task' \
    --max-depth=30 \
    ~/heap.after.bin.gz | \
  dot -o ~/graph.svg -Tsvg
```

Hopefully that will shed some light to why the leak is happening and how to fix
it!

How it works
============

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
  typeof(PyGILState_Ensure),
  typeof(PyGILState_Release),
  typeof(PyRun_SimpleFile)
) run_python;
int ret = ((run_python)payload_addr)(
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
