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

With this tool, you can take two heap snapshots at different points in time and
analyze the common objects between them (which are likely to be leaked).

To take a snapshot, run this command in the same machine / container as the
target process:

```shell
~/debug-heap$ uv run sudo python dump_heap.py --output-path=/tmp/heap.bin $(pidof python) && gzip /tmp/heap.bin
```

Save the heap somewhere, wait several minutes / hours, and run it again.

To get the largest objects that are common between both snapshots (meaning that
they are still live, since the snapshotting process forces a garbage-collection
pass):

```shell
~/debug-heap$ uv run analyze_heap.py --previous-heap-dump ~/heap.before.bin.gz top --show-parent --max-depth=30 ~/heap.after.bin.gz | less
```

This view might be sufficient to identify what's holding a (transitive)
reference to the potentially-leaked object. But this view is not always easy to
parse, so if you want to visualize that in a nice
[Graphviz](https://graphviz.org/)-produced svg, you can grab the address of an
object you want to focus on (say, `0x00005d4bbffe2100`), a few objects you want
to exclude (because they have just too many references,
`!0x7967b8ed0fe0,!0x7967eff3ad80,!0x7967e7cca000`, for example), and specify an
optional type to highlight (`asyncio.Task` is useful in async contexts, since
task leaks are surprising and often contribute a lot):

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
