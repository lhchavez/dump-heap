import argparse
import ctypes
import logging
import sys
import os
import time
import os.path
import uuid
from typing import TypedDict, Sequence
from elftools.elf.elffile import ELFFile

PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

PAGE_SIZE = 4096

SYS_MMAP = 9
SYS_MUNMAP = 11

# https://godbolt.org/#z:OYLghAFBqd5QCxAYwPYBMCmBRdBLAF1QCcAaPECAMzwBtMA7AQwFtMQByARg9KtQYEAysib0QXACx8BBAKoBnTAAUAHpwAMvAFYTStJg1DIApACYAQuYukl9ZATwDKjdAGFUtAK4sGIM2akrgAyeAyYAHI%2BAEaYxP4A7KQADqgKhE4MHt6%2B/oGp6Y4CoeFRLLHxZkl2mA6ZQgRMxATZPn4Btpj2RQwNTQQlkTFxibaNza25HQrjA2FD5SNVAJS2qF7EyOwcBACeyZhYVADUAG6oeOjHAFQQ1/wHDMsQaAwzx8gITTekHwLvn2%2B12WJgAzFYNABBPYHI5nC5XO5UZC0NKYZ7nS43EHgkxQmGHTAnMIEY53ZS7ADiAElgn0CJgAPrYN4bdEQHEQ6H7QknTGI64Uml0xoMxkAJS6mCYSmeJM5eO5sKJxxJZMFu3FXgYjKEeBYyXoADE6Oz%2BT8/m9SYDiNiwVzFYzGUwCARiHhol4xYyoAwSJgCBsniCoebiNrGcldgQEAJqKhHscHoxfsjUUokyi0b8hbT6UyWQo2cdcyKXQXWcRMDmqXnRUzJfQZZgS7Wy2LG9KlDWtTq9QbjabW73dfrDZgTfRlscTAkuccFx8vrbki6ECYAKxWDcAERnoL35jMAHoCAbj2FtLUCAA6KNH%2B2KxdL74sDCYTfbw8HmcBYgP3EoWfNUqyLWhSTBPcAFouEfIDFzVYA6H3PcNDgyFn3Ne4UKTBNGCgV4AWXbFVxjX43ywBUoSfBCTmoFDILJCB%2BWBGDlmnWd52fRdgFQIhjnQAQP0AjDF1nHcaIXJDaBw0t82ZStMA5dDn1ArxwNkzUI37cdJyUqhfhef5rWI4FSIQKjRIXOT6wlKVm2gOhLMkzN030yzBPCEAXKdGUWCdeEDEcehVQYWh5jJFznyPElQU3NwGAfeDuOObzku4kBfzMJgjwgNTwJDKzjmchIdw4VZaE4DdeD8DgtFIVBODcaxrGOBR1k2FtzFBHhSAITRytWABrEBQVBG8xsmqbpoANn0ThJBqgaGs4XgFBADQ%2BoG1Y4FgJA0ANU0yAoIzDvoeIUUMYBGTdbUhr4OgGWIdaIGiZbojCJpdk4XqPuYYhdgAeWiK8HGWg62EEQGwu%2BureCwT1gDcMRaHW7h4cwFgrvEOHSHwKs6lOTA0fqzBVFqL1tl6kkumW8LomIL6PCwZa3X1H7eCJ4hojRHdMexsJQDh1YqAMYAFAANTwTAAHdAceDmZEEEQxHYKQlfkJQ1GW3QuH0K6UBayx9A9dbIFWBMejRqDAYAL14VAufdLAzY5TpukyFwGHcTw2gkOaQnmMoKgkTaCgyARJj8Lg5vDnpBmDkYuE2mo6gEPoJl93IY/d696lmBPhniZOxn6KP/dL5pC8WYuNFWdqNi2CQKqqpbccajhjlUAAOGaoJmyQPgMIwyVuhghunCBcEIEhfx65ZeH64XhtG8bpvXya5sqjhFtIWr6o7taNq24XSF2xAQHWAhki9chKAO5IjoiVhth7vuB6Hq7R/DceF6CfAiDOz0PwZWohxDqxAZrFQ6hca61IDLRmyQOYtw4NVPey0O6Ay9DfUkqAThv37oPS6I8IBjwnmSDwZ04hzy4H/JeWh2KkBGmNCaG917zR3m3A%2Bq1bDH3oYNDhZguEOx4fwxhXN0jOEkEAA
#
# typedef void *(*fopen)(const char *, const char *);
# typedef void (*fclose)(void *);
# typedef int (*PyGILState_Ensure)();
# typedef void (*PyGILState_Release)(int);
# typedef int (*PyRun_SimpleFile)(void *, const char *);
#
# __attribute__((noreturn))
# void run_python(fopen fopen, fclose fclose, PyGILState_Ensure PyGILState_Ensure, PyGILState_Release PyGILState_Release, PyRun_SimpleFile PyRun_SimpleFile) {
#     char path[] = "/tmp/inject.py";
#     char mode[] = "r";
#     int result = -1;
#     int gil = 0;
#     void *f = fopen((const char *)path, mode);
#
#     if (f == ((void*)-1)) {
#         goto done;
#     }
#     gil = PyGILState_Ensure();
#     result = PyRun_SimpleFile(f, (const char *)path);
#     PyGILState_Release(gil);
#
#     fclose(f);
# done:
#     __asm__ volatile inline (
#         "int3\n"
#         :
#         : "a"(result)
#     );
# }
RUN_PYTHON_PAYLOAD = (
    # Add a nop sled at the beginning just in case.
    b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    b"\x55\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x83\xec\x18\x4d\x89"
    b"\xc7\x49\x89\xce\x49\x89\xd5\x48\x89\xf3\x48\x89\xf8\x48\xb9\x6a"
    b"\x65\x63\x74\x2e\x70\x79\x00\x48\x8d\x7c\x24\x08\x48\x89\x4f\x07"
    b"\x48\xb9\x2f\x74\x6d\x70\x2f\x69\x6e\x6a\x48\x89\x0f\x48\x8d\x74"
    b"\x24\x06\x66\xc7\x06\x72\x00\xff\xd0\x48\x83\xf8\xff\x74\x23\x49"
    b"\x89\xc4\x41\xff\xd5\x41\x89\xc5\x48\x8d\x74\x24\x08\x4c\x89\xe7"
    b"\x41\xff\xd7\x89\xc5\x44\x89\xef\x41\xff\xd6\x4c\x89\xe7\xff\xd3"
    b"\xeb\x03\x6a\xff\x5d\x89\xe8\xcc"
)

PYTHON_TRAMPOLINE_TEMPLATE = """
import gc
import threading

OUTPUT_PATH = "{output_path}"
DONE_PATH = "{done_path}"


def __wrapper() -> None:
    exc: BaseException | None = None
    try:
        __payload_entrypoint(OUTPUT_PATH)
    except BaseException as e:
        exc = e
    finally:
        try:
            del globals()["__payload_entrypoint"]
        except:  # noqa: E722
            pass
        gc.collect()

    with open(DONE_PATH, "w") as done_file:
        if exc is None:
            done_file.write("SUCCESS")
        else:
            done_file.write(f"ERROR: {{exc}}")


thread = threading.Thread(target=__wrapper, daemon=True)
thread.start()
"""


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_ulong)]


libc = ctypes.CDLL("libc.so.6")
libc.ptrace.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
libc.ptrace.restype = ctypes.c_uint64


class Mapping(TypedDict):
    addr_start: int
    addr_end: int
    size: int
    permissions: str
    offset: int
    device_id: str
    inode: str
    map_name: str


def load_maps(pid: int | None) -> list[Mapping]:
    """Load the tracee's maps in the tracee's address space."""

    with open(f'/proc/{pid or "self"}/maps', "r") as handle:
        output: list[Mapping] = []
        for line in handle:
            line = line.strip()
            parts = line.split()
            (addr_start, addr_end) = map(lambda x: int(x, 16), parts[0].split("-"))
            permissions = parts[1]
            offset = int(parts[2], 16)
            device_id = parts[3]
            inode = parts[4]
            map_name = parts[5] if len(parts) > 5 else ""

            output.append(
                Mapping(
                    addr_start=addr_start,
                    addr_end=addr_end,
                    size=addr_end - addr_start,
                    permissions=permissions,
                    offset=offset,
                    device_id=device_id,
                    inode=inode,
                    map_name=map_name,
                )
            )

        return output


def load_symbols(
    maps: list[Mapping], soname: str, symbols: Sequence[str]
) -> dict[str, tuple[int, int]]:
    """Find the symbols from soname in the tracee's address space."""

    for m in maps:
        if m["map_name"].endswith(f"/{soname}") and "r-xp" == m["permissions"]:
            process_lib: Mapping = m
            break
    else:
        raise Exception(f"Couldn't locate {soname!r} shared object in this process.")

    lib_base = process_lib["addr_start"]
    lib_offset = process_lib["offset"]
    lib_path = process_lib["map_name"]
    logging.debug("%s base @%x offset %x", lib_path, lib_base, lib_offset)
    symbol_addresses: dict[str, tuple[int, int]] = {}
    symbol_set = set(symbols)
    with open(lib_path, "rb") as f:
        lib_elf = ELFFile(f)

        for sym in lib_elf.get_section_by_name(".dynsym").iter_symbols():
            if sym.name not in symbols:
                continue

            st_value = sym.entry["st_value"]
            st_size = sym.entry["st_size"]
            logging.debug("%r.%r offset %x", soname, sym.name, st_value)
            symbol_addresses[sym.name] = (st_value + lib_base - lib_offset, st_size)
            logging.debug(
                "%r.%r address 0x%x", soname, sym.name, symbol_addresses[sym.name][0]
            )
    for symbol in symbol_set:
        if symbol not in symbol_addresses:
            raise Exception(
                f"Couldn't locate symbol {symbol!r} in shared object {soname!r}"
            )
    return symbol_addresses


def tracee_mmap(
    pid: int,
    addr: int,
    size: int,
    permissions: int,
    flags: int,
    fd: int | None,
    offset: int,
    syscall_rip: int,
) -> int:
    """Call the mmap(2) syscall in the tracee."""

    backup_registers = user_regs_struct()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
    try:
        registers = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

        registers.rax = SYS_MMAP
        registers.rdi = addr
        registers.rsi = size
        registers.rdx = permissions
        registers.r10 = flags
        registers.r8 = fd or -1
        registers.r9 = offset
        registers.rip = syscall_rip

        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
        libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)

        stat = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(stat[1]):
            raise Exception(f"process not stopped: {stat[1]!r}")
        if os.WSTOPSIG(stat[1]) != 5:
            raise Exception(f"stopped for some other signal: {os.WSTOPSIG(stat[1])!r}")

        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
        return registers.rax
    finally:
        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))


def tracee_munmap(pid: int, addr: int, size: int, syscall_rip: int) -> None:
    """Call the munmap(2) syscall in the tracee."""

    backup_registers = user_regs_struct()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
    try:
        registers = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

        registers.rax = SYS_MUNMAP
        registers.rdi = addr
        registers.rsi = size
        registers.rdx = 0
        registers.r10 = 0
        registers.r8 = 0
        registers.r9 = 0
        registers.rip = syscall_rip

        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
        libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)

        stat = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(stat[1]):
            raise Exception(f"process not stopped: {stat[1]!r}")
        if os.WSTOPSIG(stat[1]) != 5:
            raise Exception(f"stopped for some other signal: {os.WSTOPSIG(stat[1])!r}")

        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
        if registers.rax != 0:
            raise Exception(f"munmap failed: {registers.rax!r}")
    finally:
        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))


def write_process_memory(pid: int, address: int, data: bytes) -> None:
    """Write the supplied data into the tracee's memory at address."""

    size = len(data)
    bytes_buffer = ctypes.create_string_buffer(b"\x00" * size)
    bytes_buffer.raw = data
    local_iovec = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
    remote_iovec = iovec(ctypes.c_void_p(address), size)
    bytes_transferred = libc.process_vm_writev(
        pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
    )

    if bytes_transferred != size:
        raise Exception(f"write_process_memory failed: {bytes_transferred!r}")


def run_python(
    pid: int, payload_addr: int, stack_addr: int, symbols: dict[str, tuple[int, int]]
) -> int:
    """Execute /tmp/inject.py in the context of the tracee.

    This uses the rwx page we set up before and reuses the current stack, since
    Python likes to traverse the stack.
    """

    write_process_memory(pid, payload_addr, RUN_PYTHON_PAYLOAD)

    backup_registers = user_regs_struct()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
    try:
        registers = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

        # prepare the registers for the jump.
        registers.rdi = symbols["fopen"][0]
        registers.rsi = symbols["fclose"][0]
        registers.rdx = symbols["PyGILState_Ensure"][0]
        registers.rcx = symbols["PyGILState_Release"][0]
        registers.r8 = symbols["PyRun_SimpleFile"][0]
        registers.rbp = registers.rsp
        # Go back at least 128 bytes to avoid the red zone and align the stack.
        registers.rsp = (registers.rsp - 0x80) & 0xFFFFFFFFFFFFFFF0
        logging.debug(
            "call ((int (*)(void *, void *, void *, void *, void *))0x%x)(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)",
            payload_addr,
            registers.rdi,
            registers.rsi,
            registers.rdx,
            registers.rcx,
            registers.r8,
        )

        # perform all the side-effects of "call rax" before the jump (without
        # actually setting rax, since all we want is to change rip).
        libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(registers.rsp), registers.rip)
        registers.rsp -= 8
        # Adding 8 to rip so that it lands in the middle of the nop sled. This
        # will work even if rip needs to be adjusted after returning from a
        # syscall from the kernel's pov when we continue (not something we
        # needed to care for the single-step mmap / munmap calls).
        registers.rip = payload_addr + 8

        # change all the registers and wait for the process to get to the 0xcc (int3).
        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
        libc.ptrace(PTRACE_CONT, pid, None, None)

        stat = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(stat[1]):
            raise Exception(f"process not stopped: {stat[1]}")
        if os.WSTOPSIG(stat[1]) != 5:
            raise Exception(f"stopped for some other signal: {os.WSTOPSIG(stat[1])!r}")

        libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
        return registers.rax
    finally:
        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))


def _main() -> None:
    parser = argparse.ArgumentParser("dump-heap")
    parser.add_argument("--output-path", type=str, required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("pid", type=int)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    run_id = str(uuid.uuid4())
    done_path = f"/tmp/dump-heap-done-{args.pid}-{run_id}"
    with (
        open(
            os.path.join(os.path.dirname(__file__), "payloads/dump_heap.py"), "r"
        ) as pf,
        open("/tmp/inject.py", "w") as inf,
    ):
        inf.write(
            "\n".join(
                (
                    pf.read(),
                    PYTHON_TRAMPOLINE_TEMPLATE.format(
                        output_path=args.output_path,
                        done_path=done_path,
                    ),
                )
            ).replace(
                "__payload_entrypoint",
                "__payload_entrypoint_" + run_id.replace("-", "_"),
            )
        )

    maps = load_maps(args.pid)

    # Before we do anything with the process, let's ensure that we can find all the symbols.
    symbols = {
        **load_symbols(maps, "libc.so.6", ["fopen", "fclose", "syscall", "openat"]),
        **load_symbols(
            maps,
            "libpython3.12.so.1.0",
            ["PyGILState_Ensure", "PyGILState_Release", "PyRun_SimpleFile"],
        ),
    }

    # To avoid having to poke the syscall instruction into the current rip,
    # find the syscall opcode in the syscall libc function. That way we can
    # call syscalls directly by switching the rip to the opcode directly.
    with open(f"/proc/{args.pid}/mem", "rb") as f:
        attempts: list[str] = []
        # Every now and then, we see a process that has the wrong version of libc
        # in its maps, so we sometimes fail to find a syscall opcode in the right
        # place. To make that more robust, also look in openat.
        for sym in ("syscall", "openat"):
            f.seek(symbols[sym][0], os.SEEK_SET)
            syscall_impl = f.read(symbols[sym][1])
            syscall_offset = syscall_impl.find(b"\x0f\x05")
            if syscall_offset == -1:
                attempts.append(
                    f"'0f 05' not found in {sys}: "
                    + " ".join(f"{x:02x}" for x in syscall_impl)
                )
                continue
            syscall_rip = syscall_offset + symbols[sym][0]
            break
        else:
            for attempt in attempts:
                logging.error(attempt)
            raise Exception("syscall opcode not found")

    libc.ptrace(PTRACE_ATTACH, args.pid, None, None)

    stat = os.waitpid(args.pid, 0)
    if not os.WIFSTOPPED(stat[1]):
        raise Exception(f"process not stopped: {stat[1]!r}")
    if os.WSTOPSIG(stat[1]) != 19:
        raise Exception(f"stopped for some other signal: {os.WSTOPSIG(stat[1])!r}")
    logging.info("pid %d attached", args.pid)

    payload_addr: int | None = None
    ret = -1
    try:
        size = len(RUN_PYTHON_PAYLOAD)
        if size % PAGE_SIZE != 0:
            size += PAGE_SIZE - (size % PAGE_SIZE)
        payload_addr = tracee_mmap(
            args.pid,
            addr=0,
            size=size,
            permissions=PROT_READ | PROT_WRITE | PROT_EXEC,
            flags=MAP_PRIVATE | MAP_ANONYMOUS,
            fd=None,
            offset=0,
            syscall_rip=syscall_rip,
        )
        logging.debug("rwx page @%x", payload_addr)
        stack_addr = payload_addr + size - PAGE_SIZE

        ret = run_python(args.pid, payload_addr, stack_addr, symbols)
        # We don't run this in the finally block because if there were _any_
        # issues with running the payload, this will just make things worse.
        tracee_munmap(args.pid, addr=payload_addr, size=size, syscall_rip=syscall_rip)
    finally:
        libc.ptrace(PTRACE_DETACH, args.pid, None, None)
    if ret != 0:
        logging.error("unexpected return code %r", ret)
        sys.exit(ret)
    logging.info("ok")

    t0 = time.time()
    while time.time() - t0 < args.timeout:
        try:
            with open(done_path, "r") as f:
                contents = f.read()
                print(contents)
                break
        except:  # noqa: E722
            logging.warning("waiting...")
            time.sleep(1)
    else:
        logging.error("timed out waiting for %s", done_path)
    try:
        os.remove(done_path)
    except:  # noqa: E722
        pass


if __name__ == "__main__":
    _main()
