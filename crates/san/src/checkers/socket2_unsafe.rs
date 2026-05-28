/// Detects unsafe socket address manipulation via `socket2::SockAddr::try_init`
/// and `SockAddr::set_length`.
///
/// `SockAddr::try_init<F, T>(init: F) -> io::Result<(T, SockAddr)>`:
///   • Calls `init(storage: *mut sockaddr_storage, length: *mut socklen_t)`
///     with a zeroed-but-uninitialized `sockaddr_storage` allocation
///   • The closure must fully initialize the storage according to the target
///     address family (AF_INET, AF_INET6, AF_UNIX, etc.) — partial writes
///     leave random bytes in the address family fields, which can be
///     misinterpreted by subsequent socket syscalls (connect, bind, sendto)
///   • `*length` must be set to the exact byte count used by the chosen
///     address family structure; a wrong length causes `connect`/`bind` to
///     read out-of-bounds or ignore critical fields (e.g. port, scope_id)
///   • The closure must also set `ss_family` correctly — a wrong address
///     family causes the kernel to interpret the rest of the struct as the
///     wrong type
///
/// `SockAddr::set_length(length: socklen_t)`:
///   • Directly overwrites the stored address length without validating
///     that the new length matches the actual size of the address family
///     struct in the storage buffer
///   • Setting too large a value causes the OS to read beyond the
///     initialized data; too small a value truncates required fields
///     (e.g. truncating an IPv6 address's scope_id is a silent routing error)
///
/// Safe alternative: use the safe constructors `SockAddr::from(SocketAddrV4)`,
/// `SockAddr::from(SocketAddrV6)`, or platform-specific helpers; only use
/// `try_init` when interfacing with a socket family not supported by those.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct Socket2Unsafe;

impl Checker for Socket2Unsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.starts_with("socket2::") {
                continue;
            }

            let (fn_name, note) = if path == "socket2::SockAddr::try_init" {
                (
                    "SockAddr::try_init",
                    "init closure must fully set ss_family, the appropriate address fields, \
                     and *len to the exact family struct size; partial initialization or wrong \
                     length causes connect/bind to misread address data or read beyond the buffer",
                )
            } else if path == "socket2::SockAddr::set_length" {
                (
                    "SockAddr::set_length",
                    "overwrites the stored address length without validating it matches the \
                     family struct size in the buffer; too large reads past initialized data; \
                     too small truncates fields (e.g. IPv6 scope_id)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "socket2_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
