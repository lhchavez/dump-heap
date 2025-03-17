#[macro_use(defer)]
extern crate scopeguard;

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs;
use std::io::IoSlice;
use std::num::NonZeroUsize;
use std::os::unix::fs::FileExt;
use std::path::{self, Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Parser;
use elf::endian::AnyEndian;
use elf::ElfStream;
use log::{debug, info};
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use procmaps::{self, Mappings};
use serde::Serialize;
use tinytemplate::TinyTemplate;
use uuid::Uuid;

const PAGE_SIZE: usize = 4096;

/// An address in the tracee process' address space.
#[derive(Debug, Copy, Clone, PartialEq)]
struct TraceeAddress(usize);

impl From<TraceeAddress> for usize {
    fn from(val: TraceeAddress) -> Self {
        val.0
    }
}

impl From<TraceeAddress> for u64 {
    fn from(val: TraceeAddress) -> Self {
        val.0 as u64
    }
}

impl std::ops::Add for TraceeAddress {
    type Output = Self;

    fn add(self, other: TraceeAddress) -> Self {
        Self(self.0 + other.0)
    }
}
impl std::ops::Add<usize> for TraceeAddress {
    type Output = Self;

    fn add(self, other: usize) -> Self {
        Self(self.0 + other)
    }
}

impl std::fmt::LowerHex for TraceeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::LowerHex::fmt(&val, f)
    }
}

/// A range in the tracee process' address space.
struct TraceeRange {
    base: TraceeAddress,
    size: usize,
}

/// Shellcode to run an arbitrary Python payload
/// https://godbolt.org/#g:!((g:!((g:!((h:codeEditor,i:(filename:'1',fontScale:14,fontUsePx:'0',j:1,lang:c%2B%2B,selection:(endColumn:2,endLineNumber:17,positionColumn:1,positionLineNumber:1,selectionStartColumn:2,selectionStartLineNumber:17,startColumn:1,startLineNumber:1),source:'typedef+int+(*PyGILState_Ensure)()%3B%0Atypedef+void+(*PyGILState_Release)(int)%3B%0Atypedef+int+(*PyRun_SimpleString)(const+char+*)%3B%0A%0A__attribute__((noreturn))%0Avoid+run_python(PyGILState_Ensure+PyGILState_Ensure,+PyGILState_Release+PyGILState_Release,+PyRun_SimpleString+PyRun_SimpleString)+%7B%0A++++int+gil+%3D+PyGILState_Ensure()%3B%0A++++static+const+char+*code+%3D+%22This+payload+will+be+modified+at+runtime%22%3B%0A++++int+result+%3D+PyRun_SimpleString(code)%3B%0A++++PyGILState_Release(gil)%3B%0A%0A++++__asm__+volatile+inline+(%0A++++++++%22int3%5Cn%22%0A++++++++:%0A++++++++:+%22a%22(result)%0A++++)%3B%0A%7D'),l:'5',n:'0',o:'C%2B%2B+source+%231',t:'0')),k:33.333333333333336,l:'4',n:'0',o:'',s:0,t:'0'),(g:!((h:compiler,i:(compiler:clang_trunk,filters:(b:'0',binary:'1',binaryObject:'0',commentOnly:'0',debugCalls:'1',demangle:'0',directives:'0',execute:'1',intel:'0',libraryCode:'0',trim:'1',verboseDemangling:'0'),flagsViewOpen:'1',fontScale:14,fontUsePx:'0',j:1,lang:c%2B%2B,libs:!(),options:'-Oz',overrides:!(),selection:(endColumn:1,endLineNumber:1,positionColumn:1,positionLineNumber:1,selectionStartColumn:1,selectionStartLineNumber:1,startColumn:1,startLineNumber:1),source:1),l:'5',n:'0',o:'+x86-64+clang+(trunk)+(Editor+%231)',t:'0')),k:33.333333333333336,l:'4',n:'0',o:'',s:0,t:'0'),(g:!((h:output,i:(compilerName:'x86-64+clang+(trunk)',editorid:1,fontScale:14,fontUsePx:'0',j:1,wrap:'1'),l:'5',n:'0',o:'Output+of+x86-64+clang+(trunk)+(Compiler+%231)',t:'0')),k:33.33333333333333,l:'4',n:'0',o:'',s:0,t:'0')),l:'2',n:'0',o:'',t:'0')),version:4
///
/// typedef int (*PyGILState_Ensure)();
/// typedef void (*PyGILState_Release)(int);
/// typedef int (*PyRun_SimpleString)(const char *);
///
/// __attribute__((noreturn))
/// void run_python(PyGILState_Ensure PyGILState_Ensure, PyGILState_Release PyGILState_Release, PyRun_SimpleString PyRun_SimpleString) {
///     int gil = PyGILState_Ensure();
///     static const char *code = "This payload will be modified at runtime";
///     int result = PyRun_SimpleString(code);
///     PyGILState_Release(gil);
///
///     __asm__ volatile inline (
///         "int3\n"
///         :
///         : "a"(result)
///     );
/// }
static RUN_PYTHON_PAYLOAD: &[u8] = &[
    // Add a nop sled at the beginning just in case.
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x55, 0x41, 0x56, 0x53, 0x48, 0x89, 0xD3, 0x49, 0x89, 0xF6, 0xFF, 0xD7, 0x89, 0xC5, 0x48, 0x8D,
    // Note the 0C 00 00 00 here: it's the offset to the start of the NUL-terminated code.
    0x3D, 0x0C, 0x00, 0x00, 0x00, 0xFF, 0xD3, 0x89, 0xC3, 0x89, 0xEF, 0x41, 0xFF, 0xD6, 0x89, 0xD8,
    0xCC, // The NUL-terminated code is added here.
];

/// The payload that dumps bytes.
static DUMP_HEAP_PAYLOAD: &str = include_str!("./payloads/dump_heap.py");

/// The trampoline that is appended to the payload that starts executing it in a different thread.
static TRAMPOLINE_PAYLOAD: &str = include_str!("./payloads/trampoline.py");

#[derive(Serialize)]
struct TemplateContext {
    output_path: PathBuf,
    done_path: PathBuf,
}

/// Dumps the heap of a running Python program.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Pid of the running Python process.
    #[arg()]
    pid: i32,

    /// Path to the dumped heap.
    #[arg(long)]
    output: PathBuf,

    /// Path of the payload (optional).
    /// The payload must consist of a single function with no global imports and the following signature:
    ///
    /// ```python
    /// def __payload_entrypoint(output_path: str) -> None:
    ///     # Imports must be done here.
    ///     import sys
    ///     # The rest of the payload.
    ///     pass
    /// ```
    ///
    /// Imports can still be done, but that has to be done inside the function.
    #[clap(verbatim_doc_comment)]
    #[arg(long)]
    payload: Option<PathBuf>,

    /// Amount of time to wait before giving up in seconds.
    #[arg(long, value_parser = parse_duration, default_value = "60")]
    timeout: Duration,
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

/// Build the shellcode that will be injected into the tracee.
fn build_shellcode<P1, P2, P3>(
    run_id: &Uuid,
    done_path: P1,
    output_path: P2,
    payload_path: Option<P3>,
) -> Result<Vec<u8>>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    P3: AsRef<Path> + std::fmt::Debug,
    std::path::PathBuf: std::convert::From<P1>,
    std::path::PathBuf: std::convert::From<P2>,
    std::path::PathBuf: std::convert::From<P3>,
{
    let mut shellcode = Vec::<u8>::new();
    shellcode.extend(RUN_PYTHON_PAYLOAD);
    let mut payload = String::new();
    if let Some(payload_path) = payload_path {
        payload.push_str(
            &fs::read_to_string(&payload_path)
                .with_context(|| format!("read {payload_path:#?}"))?,
        );
    } else {
        payload.push_str(DUMP_HEAP_PAYLOAD);
    }
    payload.push_str("\n\n");

    let mut tt = TinyTemplate::new();
    const TRAMPOLINE_NAME: &str = "trampoline";
    tt.add_template(TRAMPOLINE_NAME, TRAMPOLINE_PAYLOAD)?;
    payload.push_str(&tt.render(
        TRAMPOLINE_NAME,
        &TemplateContext {
            output_path: path::absolute(output_path)?,
            done_path: done_path.into(),
        },
    )?);
    shellcode.extend(
        payload
            .replace(
                "__payload_entrypoint",
                &format!(
                    "__payload_entrypoint_{}",
                    run_id.to_string().replace("-", "_")
                ),
            )
            .as_bytes(),
    );
    // We need the payload to be NUL-terminated. mmap(2) will guarantee that the returned region
    // will be filled with zeroes, but if the trampoline + payload size happens to be page-aligned,
    // we will segfault unless this extra explicit NUL is added!
    shellcode.extend(b"\x00");

    Ok(shellcode)
}

/// Load the specified symbols from a running process.
fn load_symbols(
    mappings: &Mappings,
    soname: &str,
    symbols: &[&str],
) -> Result<HashMap<String, TraceeRange>> {
    let (mapping, mapped_file) = {
        let mut found_mapping: Option<(&procmaps::Map, &str)> = None;
        for mapping in mappings.iter() {
            if !mapping.perms.executable {
                continue;
            }
            if let procmaps::Path::MappedFile(mapped_file) = &mapping.pathname {
                if !mapped_file.contains(soname) {
                    continue;
                }
                found_mapping = Some((mapping, mapped_file));
                break;
            }
        }
        found_mapping.unwrap()
    };
    let f = std::fs::File::open(mapped_file).with_context(|| format!("open {mapped_file}"))?;
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(f)
        .with_context(|| format!("parse {mapped_file}"))?;
    let (sym_table, string_table) = elf
        .dynamic_symbol_table()
        .context("parse .dynsym section")?
        .ok_or(anyhow!("find .dynsym section"))?;
    let mut symbol_name_set = HashSet::<String>::new();
    for symbol_name in symbols {
        symbol_name_set.insert(symbol_name.to_string());
    }
    let mut result = HashMap::<String, TraceeRange>::new();
    for sym in sym_table.iter() {
        if sym.st_name == 0 {
            continue;
        }
        let sym_name = string_table
            .get(sym.st_name as usize)
            .context("invalid symbol name")?;
        if !symbol_name_set.contains(sym_name) {
            continue;
        }
        result.insert(
            sym_name.to_string(),
            TraceeRange {
                base: TraceeAddress(sym.st_value as usize + mapping.base - mapping.offset),
                size: sym.st_size as usize,
            },
        );
    }
    Ok(result)
}

/// Call the mmap(2) syscall in the tracee.
fn tracee_mmap_anonymous(
    pid: Pid,
    syscall_rip: TraceeAddress,
    addr: Option<TraceeAddress>,
    length: NonZeroUsize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<TraceeAddress> {
    let backup_registers = ptrace::getregs(pid).context("get backup registers")?;
    defer! {
        ptrace::setregs(pid, backup_registers).unwrap();
    }
    let mut registers = backup_registers;

    registers.rax = nix::libc::SYS_mmap as u64;
    registers.rdi = addr.unwrap_or(TraceeAddress(0)).into();
    registers.rsi = length.get() as u64;
    registers.rdx = prot.bits() as u64;
    registers.r10 = (MapFlags::MAP_ANONYMOUS | flags).bits() as u64;
    registers.r8 = u64::MAX; // -1
    registers.r9 = 0u64;
    registers.rip = syscall_rip.into();
    ptrace::setregs(pid, registers).context("set registers")?;
    ptrace::step(pid, None).context("single step")?;
    match waitpid(pid, None).with_context(|| format!("waitpid {:#?}", pid))? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
        status => {
            bail!("process stopped with unexpected status {:#?}", status);
        }
    }

    let registers = ptrace::getregs(pid).context("get registers")?;
    ensure!(registers.rax != u64::MAX, "{}", registers.rax);
    ensure!(registers.rax != 0, "{}", registers.rax);
    Ok(TraceeAddress(registers.rax as usize))
}

/// Call the munmap(2) syscall in the tracee.
fn tracee_munmap(
    pid: Pid,
    syscall_rip: TraceeAddress,
    addr: TraceeAddress,
    length: NonZeroUsize,
) -> Result<()> {
    let backup_registers = ptrace::getregs(pid).context("get backup registers")?;
    defer! {
        ptrace::setregs(pid, backup_registers).unwrap();
    }
    let mut registers = backup_registers;

    registers.rax = nix::libc::SYS_munmap as u64;
    registers.rdi = addr.into();
    registers.rsi = length.get() as u64;
    registers.rdx = 0;
    registers.r10 = 0;
    registers.r8 = 0;
    registers.r9 = 0;
    registers.rip = syscall_rip.into();
    ptrace::setregs(pid, registers).context("set registers")?;
    ptrace::step(pid, None).context("single step")?;
    match waitpid(pid, None).with_context(|| format!("waitpid {:#?}", pid))? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
        status => {
            bail!("process stopped with unexpected status {:#?}", status);
        }
    }

    let registers = ptrace::getregs(pid).context("get registers")?;
    ensure!(registers.rax == 0, "{}", registers.rax);
    Ok(())
}

/// Execute the provided shellcode in the context of the tracee.
///
/// This uses the rwx page we set up before to write the shellcode and reuses the current stack,
/// since Python likes to traverse the stack.
fn run_python_shellcode(
    pid: Pid,
    shellcode: &[u8],
    shellcode_addr: TraceeAddress,
    symbols: HashMap<String, TraceeRange>,
) -> Result<()> {
    // Write the shellcode
    process_vm_writev(
        pid,
        &[IoSlice::new(shellcode)],
        &[RemoteIoVec {
            base: shellcode_addr.into(),
            len: shellcode.len(),
        }],
    )
    .context("process_wm_writev")?;

    let backup_registers = ptrace::getregs(pid).context("get backup registers")?;
    defer! {
        ptrace::setregs(pid, backup_registers).unwrap();
    }
    let mut registers = backup_registers;

    // Prepare the registers for the jump
    registers.rdi = symbols
        .get("PyGILState_Ensure")
        .ok_or(anyhow!("PyGILState_Ensure"))?
        .base
        .into();
    registers.rsi = symbols
        .get("PyGILState_Release")
        .ok_or(anyhow!("PyGILState_Release"))?
        .base
        .into();
    registers.rdx = symbols
        .get("PyRun_SimpleString")
        .ok_or(anyhow!("PyRun_SimpleString"))?
        .base
        .into();
    registers.r10 = 0;
    registers.r8 = 0;
    registers.r9 = 0;
    // Go back at least 128 bytes to avoid the red zone and align the stack.
    registers.rsp = (registers.rsp - 0x80) & 0xFFFFFFFFFFFFFFF0;

    // perform all the side-effects of "call rax" before the jump (without
    // actually setting rax, since all we want is to change rip).
    ptrace::write(pid, registers.rsp as *mut c_void, registers.rip as i64).context("push rip")?;
    registers.rsp -= 8;
    // Adding 8 to rip so that it lands in the middle of the nop sled. This
    // will work even if rip needs to be adjusted after returning from a
    // syscall from the kernel's pov when we continue (not something we
    // needed to care for the single-step mmap / munmap calls).
    registers.rip = (shellcode_addr + 8usize).into();

    // change all the registers and wait for the process to get to the 0xcc (int3).
    ptrace::setregs(pid, registers).context("set registers")?;
    ptrace::cont(pid, None).context("continue")?;
    match waitpid(pid, None).with_context(|| format!("waitpid {:#?}", pid))? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
        status => {
            bail!("process stopped with unexpected status {:#?}", status);
        }
    }

    let registers = ptrace::getregs(pid).context("get registers")?;
    ensure!(registers.rax == 0, "{}", registers.rax);
    Ok(())
}

fn run_python<P1, P2>(pid: Pid, output_path: P1, payload_path: Option<P2>) -> Result<PathBuf>
where
    P1: AsRef<Path> + std::fmt::Debug,
    P2: AsRef<Path> + std::fmt::Debug,
    std::path::PathBuf: std::convert::From<P1>,
    std::path::PathBuf: std::convert::From<P2>,
{
    let run_id = Uuid::new_v4();
    let done_path = PathBuf::from(format!("/tmp/dump-heap-done-{}-{}", pid, run_id));

    let shellcode = build_shellcode(&run_id, &done_path, output_path, payload_path)
        .context("build shellcode")?;

    // Before we do anything with the process, let's ensure that we can find all the symbols.
    let mappings = Mappings::from_pid(pid.into())?;
    let symbols: HashMap<String, TraceeRange> =
        load_symbols(&mappings, "libc.so.6", &["syscall", "openat"])
            .context("load symbols from libc.so.6")?
            .into_iter()
            .chain(
                load_symbols(
                    &mappings,
                    "libpython3.",
                    &[
                        "PyGILState_Ensure",
                        "PyGILState_Release",
                        "PyRun_SimpleString",
                    ],
                )
                .context("load symbols from libpython3")?,
            )
            .collect();

    // To avoid having to poke the syscall instruction into the current rip,
    // find the syscall opcode in the syscall libc function. That way we can
    // call syscalls directly by switching the rip to the opcode directly.
    let syscall_rip = {
        let f = std::fs::File::open(format!("/proc/{}/mem", pid))
            .with_context(|| format!("open /proc/{}/mem", pid))?;
        // Every now and then, we see a process that has the wrong version of libc
        // in its maps, so we sometimes fail to find a syscall opcode in the right
        // place. To make that more robust, also look in openat.
        let mut syscall_rip: Option<TraceeAddress> = None;
        for sym in &symbols {
            let mut code = vec![0u8; sym.1.size];
            f.read_exact_at(&mut code, sym.1.base.into())
                .with_context(|| format!("read symbol {}", sym.0))?;
            if let Some(syscall_offset) = code.windows(2).position(|s| s == [0x0f, 0x05]) {
                syscall_rip = Some(TraceeAddress(syscall_offset) + sym.1.base);
                break;
            }
        }
        syscall_rip.ok_or(anyhow!("syscall opcode not found"))
    }?;

    // Attach to the process with ptrace(2).
    ptrace::attach(pid).with_context(|| format!("ptrace::attach {}", pid))?;
    match waitpid(pid, None).with_context(|| format!("waitpid {}", pid))? {
        WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
        status => {
            bail!("process stopped with unexpected status {:#?}", status);
        }
    }
    defer! {
        ptrace::detach(pid, None).unwrap();
    }
    info!("pid {} attached", pid);

    // Allocate a rwx region using mmap(2) in the tracee.
    let mut shellcode_size = shellcode.len();
    if shellcode_size % PAGE_SIZE != 0 {
        shellcode_size += PAGE_SIZE - (shellcode_size % PAGE_SIZE);
    };
    let shellcode_addr = tracee_mmap_anonymous(
        pid,
        syscall_rip,
        None,
        NonZeroUsize::new(shellcode_size).ok_or(anyhow!("invalid size"))?,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
        MapFlags::MAP_PRIVATE,
    )
    .context("tracee_mmap_anonymous")?;
    debug!("mapped address {:x}", shellcode_addr);

    // Run the shellcode.
    run_python_shellcode(pid, &shellcode, shellcode_addr, symbols)
        .context("run_python_shellcode")?;

    // We don't run this in a defer block because if there were _any_
    // issues with running the payload, this will just make things worse.
    tracee_munmap(
        pid,
        syscall_rip,
        shellcode_addr,
        NonZeroUsize::new(shellcode_size).ok_or(anyhow!("invalid size"))?,
    )
    .context("tracee_munmap")?;

    Ok(done_path)
}

fn wait_for_result(done_path: &PathBuf, timeout: Duration) -> Result<()> {
    let now = Instant::now();
    while !done_path.exists() {
        if now.elapsed() < timeout {
            info!("waiting...");
            sleep(Duration::from_secs(1));
        } else {
            bail!("timed out waiting for {:#?}", done_path);
        }
    }
    fs::remove_file(done_path)?;

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    let done_path = run_python(Pid::from_raw(args.pid), &args.output, args.payload.as_ref())
        .context("run_python")?;

    info!("injected code, waiting for result...");

    wait_for_result(&done_path, args.timeout)?;

    info!("wrote dump to {:#?}", args.output);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    #[test]
    fn it_works() {
        let tmp_dir =
            TempDir::with_prefix("dump-heap-").expect("Failed to create temporary directory");
        let mut child = Command::new("python")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute Python");

        let mut buf = vec![0u8; 4096];
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let mut stdout = child.stdout.take().expect("Failed to open stdout");
        stdin
            .write_all(b"big_string = 'helloworld' * 1024 * 1024; print(0)\n")
            .expect("Failed to write print");
        let read = stdout.read(&mut buf).expect("Failed to read stdout");
        assert_eq!(&buf[..read], b"0\n");

        let output_path: PathBuf = tmp_dir.path().join("output.bin");
        let done_path = run_python(
            Pid::from_raw(child.id() as i32),
            &output_path,
            None::<PathBuf>,
        )
        .expect("Failed to run_python");
        wait_for_result(&done_path, Duration::from_secs(5)).expect("Failed to wait for result");
        stdin
            .write_all(b"print(1)\nexit()\n")
            .expect("Failed to write exit");
        let read = stdout.read(&mut buf).expect("Failed to read stdout");
        assert_eq!(&buf[..read], b"1\n");

        let result = Command::new("uv")
            .arg("run")
            .arg("analyze_heap.py")
            .arg("top")
            .arg(output_path)
            .stderr(Stdio::inherit())
            .output()
            .expect("Failed to execute analyze_heap.py");
        assert!(result.status.success());
        let expected = b"helloworldhelloworld";
        if let None = result
            .stdout
            .windows(expected.len())
            .position(|s| s == expected)
        {
            assert!(
                false,
                "{:#?} did not contain {:#?}",
                String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(expected),
            );
        }
    }
}
