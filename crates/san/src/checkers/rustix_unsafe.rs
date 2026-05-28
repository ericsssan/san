/// Detects unsafe operations from the `rustix` crate — a modern, type-safe
/// syscall library used as an alternative to `nix` and `libc`.
///
/// `rustix::runtime::exit_thread(status)`:
///   • Calls the `exit` or `exit_group` syscall directly, terminating the
///     current thread without running any Rust destructors, RAII guards,
///     `Drop` implementations, or atexit handlers
///   • All stack-allocated resources (file handles, locks, Box, Vec, etc.)
///     leak; mutexes held at exit time stay locked (deadlock for other threads)
///   • The process may be left in a partially-torn-down state if called from
///     a non-main thread without prior cleanup
///
/// `rustix::runtime::kernel_fork()`:
///   • Directly calls the `fork(2)` syscall via Linux `clone` without libc
///   • In a multi-threaded parent, only the calling thread survives in the child;
///     all mutexes held by other threads are left locked (deadlock if child
///     calls anything that acquires them, including `malloc`)
///   • Signal handlers, `pthread_atfork` handlers, and libc internal state
///     may be in inconsistent states in the child
///
/// `rustix::runtime::execve` / `execveat`:
///   • Replaces the current process image; memory, fds, and state are discarded
///   • All Rust destructors, Drop implementations, and RAII guards are bypassed
///   • `argv` and `envp` must be valid null-terminated arrays of valid C strings
///     pointing to memory that is valid at the time of the syscall
///
/// `rustix::runtime::kernel_brk(addr)`:
///   • Directly moves the program's data-segment break via `brk(2)`
///   • Moving the break below existing allocations causes `malloc`/`free` to
///     access unmapped memory (heap corruption, UB)
///
/// `rustix::runtime::set_thread_area` / `arm_set_tls` / `set_fs`:
///   • Overwrites the TLS (Thread Local Storage) segment descriptor or register
///   • If the new TLS base is incorrect, every thread-local variable access in
///     the current thread produces undefined behaviour (wrong addresses)
///
/// `rustix::runtime::tkill(tid, sig)`:
///   • Sends a signal to a thread identified by `tid`; if the tid is stale
///     (the thread already exited and the TID was reused), the signal is
///     delivered to the wrong thread
///
/// `rustix::runtime::kernel_sigaction`:
///   • Installs a signal handler; handler must only call async-signal-safe
///     functions; calling malloc, locking a mutex, or using stdio is UB
///
/// `rustix::io::close(raw_fd)`:
///   • Closes a raw file descriptor without ownership tracking; if `raw_fd` is
///     still owned by a Rust type (OwnedFd, File, TcpStream…), double-close
///     triggers UB; if the fd was already closed and reused, closes the new owner
///
/// `rustix::stdio::take_stdin` / `take_stdout` / `take_stderr`:
///   • Transfers ownership of the standard I/O file descriptors to the caller;
///     any subsequent code that reads stdin / writes stdout / writes stderr via
///     the Rust standard library operates on potentially-closed or reallocated fds
///
/// `rustix::mm::mmap` / `mmap_anonymous` / `munmap` / `mremap` / `mremap_fixed`:
///   • Raw `mmap`/`munmap`/`mremap` syscalls; all memory-safety invariants are
///     the caller's responsibility; the returned region must not alias any
///     existing Rust reference; `munmap` invalidates all pointers/references
///     into the region; `mremap` with MREMAP_FIXED may silently overwrite a
///     mapping at the target address
///
/// `rustix::mm::madvise`:
///   • MADV_DONTNEED / MADV_FREE can cause subsequent reads of live pages to
///     return zeros or stale data (kernel may reclaim or zero the pages);
///     if a Rust reference points into the advised range, reads become UB
///
/// `rustix::mm::msync`:
///   • Addr and len must point into a valid memory mapping; msync on unmapped
///     or freed memory is UB (SIGSEGV or silent data corruption)
///
/// `rustix::pipe::vmsplice`:
///   • Splices user-space memory into a kernel pipe ring buffer; the kernel
///     reads from the described memory pages at a future point in time after
///     vmsplice returns; if that memory is freed or mutated before the kernel
///     finishes, the pipe will contain stale or garbage data (information leak)
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RustixUnsafe;

impl Checker for RustixUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.starts_with("rustix::") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::exit_thread") && path.contains("runtime")
            {
                (
                    "rustix::runtime::exit_thread",
                    "terminates the current thread via raw syscall — all Rust destructors, \
                     Drop implementations, and RAII guards are bypassed; mutexes held at \
                     exit remain locked, causing deadlock for any other thread that tries \
                     to acquire them; heap allocations and file handles leak",
                )
            } else if path.ends_with("::kernel_fork") && path.contains("runtime") {
                (
                    "rustix::runtime::kernel_fork",
                    "raw fork without libc: in a multi-threaded parent only the calling thread \
                     survives in the child; other threads' mutexes are left locked — any \
                     subsequent malloc, I/O, or locking in the child may deadlock or corrupt state; \
                     always exec immediately after fork in the child path",
                )
            } else if (path.ends_with("::execve") || path.ends_with("::execveat"))
                && path.contains("runtime")
            {
                (
                    "rustix::runtime::execve",
                    "replaces the current process image without running any Rust destructors or \
                     RAII cleanup; argv and envp must be valid null-terminated arrays of valid C \
                     strings valid at the time of the call; the process state is fully replaced",
                )
            } else if path.ends_with("::kernel_brk") && path.contains("runtime") {
                (
                    "rustix::runtime::kernel_brk",
                    "moves the data-segment break via brk(2); moving it below existing malloc \
                     allocations causes the heap allocator to access unmapped memory \
                     (heap corruption, immediate UB); only safe when no dynamic allocations exist",
                )
            } else if (path.ends_with("::set_thread_area")
                || path.ends_with("::arm_set_tls")
                || path.ends_with("::set_fs"))
                && path.contains("runtime")
            {
                (
                    "rustix::runtime::set_tls",
                    "overwrites the TLS base register/segment for the current thread; if the new \
                     base is incorrect, every thread-local variable access (including the Rust \
                     stdlib's own TLS) is immediately invalid (wrong addresses, UB); use only \
                     when implementing a custom TLS scheme",
                )
            } else if path.ends_with("::tkill") && path.contains("runtime") {
                (
                    "rustix::runtime::tkill",
                    "sends a signal to a thread by TID; if the TID is stale (thread exited and \
                     TID was reused by a new thread), the signal is delivered to the wrong \
                     thread — unexpected signal delivery is UB if the handler is not async-signal-safe",
                )
            } else if path.ends_with("::kernel_sigaction") && path.contains("runtime") {
                (
                    "rustix::runtime::kernel_sigaction",
                    "installs a signal handler via raw sigaction(2) without libc wrapping; \
                     the handler must only call async-signal-safe functions; calling malloc, \
                     locking a mutex, or using stdio inside the handler is UB; the previous \
                     action stored in `old_action` may itself be unsafe to call",
                )
            } else if path.ends_with("rustix::io::close") || path == "rustix::io::close" {
                (
                    "rustix::io::close",
                    "closes a raw file descriptor without ownership checks; if this fd is still \
                     owned by an OwnedFd, File, TcpStream, or any other Rust I/O type, the \
                     object will later close an already-closed or reused fd (double-close / \
                     wrong-fd close, UB); use OwnedFd's drop to manage fd lifetime safely",
                )
            } else if (path.ends_with("::take_stdin")
                || path.ends_with("::take_stdout")
                || path.ends_with("::take_stderr"))
                && path.contains("stdio")
            {
                (
                    "rustix::stdio::take_stdio",
                    "transfers ownership of a standard I/O file descriptor; subsequent calls \
                     to print!, eprintln!, or any Rust code that reads stdin now operate on a \
                     potentially-closed or reused fd; the caller must not allow the returned \
                     OwnedFd to drop unless all other users of that stdio stream have finished",
                )
            } else if (path.ends_with("::vmsplice")) && path.contains("pipe") {
                (
                    "rustix::pipe::vmsplice",
                    "the kernel reads from the described user-space memory pages at an \
                     unspecified future time after vmsplice returns; if the memory is freed, \
                     reallocated, or mutated before the kernel finishes reading, the pipe \
                     contains stale or garbage data (information leak, potential UB)",
                )
            } else if (path.ends_with("::mmap") || path.ends_with("::mmap_anonymous"))
                && path.contains("mm")
            {
                (
                    "rustix::mm::mmap",
                    "the returned region must not alias any existing Rust reference; for \
                     file-backed mappings, the fd must remain valid and must be opened with \
                     permissions consistent with prot; the mapping must be explicitly \
                     munmap'd before the backing resource is freed",
                )
            } else if path.ends_with("::munmap") && path.contains("mm") {
                (
                    "rustix::mm::munmap",
                    "all pointers and references into the unmapped region become dangling \
                     after this call — any subsequent access is use-after-free (UB); \
                     ensure no live Rust borrows cover the region at the time of unmap",
                )
            } else if (path.ends_with("::mremap") || path.ends_with("::mremap_fixed"))
                && path.contains("mm")
            {
                (
                    "rustix::mm::mremap",
                    "extends, shrinks, or moves a mapping; all existing pointers to the old \
                     range become dangling if the mapping was moved; mremap_fixed may silently \
                     unmap any mapping already at the target address",
                )
            } else if path.ends_with("::madvise") && path.contains("mm") {
                (
                    "rustix::mm::madvise",
                    "MADV_DONTNEED / MADV_FREE can reclaim or zero pages that are still pointed \
                     to by live Rust references — subsequent reads through those references \
                     return zeros or stale data instead of the written values (UB); \
                     addr must be within a valid mapping",
                )
            } else if path.ends_with("::msync") && path.contains("mm") {
                (
                    "rustix::mm::msync",
                    "addr and len must refer to an active memory-mapped region; msync on \
                     unmapped or freed memory is UB (SIGSEGV or silent data corruption)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "rustix_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
