#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::mir;
use rustc_middle::ty::TyCtxt;

pub mod analysis;
pub mod checkers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub span: rustc_span::Span,
    pub message: String,
}

pub trait Checker: Send + Sync {
    /// Called once per MIR body (function, closure, const, etc.).
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &mir::Body<'tcx>) -> Vec<Finding> {
        let _ = (tcx, body);
        Vec::new()
    }

    /// Called once per crate for checkers that need whole-crate HIR visibility
    /// (e.g. impl-block analysis). Default: no-op.
    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let _ = tcx;
        Vec::new()
    }
}

/// A checker that operates on pre-computed flow-sensitive analysis results.
/// `check_flow` is called once per MIR body after the fixpoint has converged.
pub trait FlowChecker: Send + Sync {
    fn check_flow<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &mir::Body<'tcx>,
        flow: &analysis::FlowResults,
    ) -> Vec<Finding>;
}

static CHECKERS: &[&(dyn Checker + Sync)] = &[
    &checkers::arc_from_raw::ArcFromRaw,
    &checkers::clone_to_uninit_impl::CloneToUninitImpl,
    &checkers::global_alloc_impl::GlobalAllocImpl,
    &checkers::assume_init::AssumeInit,
    &checkers::atomic_from_ptr::AtomicFromPtr,
    &checkers::box_from_raw::BoxFromRaw,
    &checkers::char_from_u32_unchecked::CharFromU32Unchecked,
    &checkers::cstr_from_ptr::CStrFromPtr,
    &checkers::hint_assert_unchecked::HintAssertUnchecked,
    &checkers::cstring_as_ptr::CStringAsPtr,
    &checkers::layout_unchecked::LayoutUnchecked,
    &checkers::manually_drop::ManuallyDropOps,
    &checkers::mem_forget::MemForget,
    &checkers::mem_transmute::MemTransmute,
    &checkers::mem_transmute_copy::MemTransmuteCopy,
    &checkers::mem_uninitialized::MemUninitialized,
    &checkers::mem_zeroed_generic::MemZeroedGeneric,
    &checkers::missing_send_sync_bounds::MissingSendSyncBounds,
    &checkers::nonnull_deref::NonNullDeref,
    &checkers::osstr_encoded_bytes::OsStrEncodedBytes,
    &checkers::nonnull_new_unchecked::NonNullNewUnchecked,
    &checkers::nonzero_new_unchecked::NonZeroNewUnchecked,
    &checkers::pin_new_unchecked::PinNewUnchecked,
    &checkers::ptr_arith::PtrArith,
    &checkers::ptr_as_ref::PtrAsRef,
    &checkers::ptr_copy::PtrCopy,
    &checkers::ptr_drop_in_place::PtrDropInPlace,
    &checkers::ptr_read::PtrRead,
    &checkers::ptr_write::PtrWrite,
    &checkers::raw_allocator::RawAllocator,
    &checkers::raw_fd::RawFd,
    &checkers::slice_align_to::SliceAlignTo,
    &checkers::slice_from_raw_parts::SliceFromRawParts,
    &checkers::slice_get_unchecked::SliceGetUnchecked,
    &checkers::str_from_utf8_unchecked::StrFromUtf8Unchecked,
    &checkers::str_mutation::StrMutation,
    &checkers::thread_spawn_unchecked::ThreadSpawnUnchecked,
    &checkers::union_field::UnionField,
    &checkers::unchecked_int_arith::UncheckedIntArith,
    &checkers::unreachable_unchecked::UnreachableUnchecked,
    &checkers::unwrap_unchecked::UnwrapUnchecked,
    &checkers::inline_asm::InlineAsm,
    &checkers::into_raw::IntoRaw,
    &checkers::pre_exec::PreExec,
    &checkers::ptr_provenance::PtrProvenance,
    &checkers::static_mut::StaticMut,
    &checkers::unsafecell_get::UnsafeCellGet,
    &checkers::vec_from_raw_parts::VecFromRawParts,
    &checkers::vec_set_len::VecSetLen,
    &checkers::waker_from_raw::WakerFromRaw,
    &checkers::cstr_from_bytes_unchecked::CStrFromBytesUnchecked,
    &checkers::cstring_from_raw::CStringFromRaw,
    &checkers::foreign_fn::ForeignFn,
    &checkers::string_from_raw_parts::StringFromRawParts,
    &checkers::float_to_int_unchecked::FloatToIntUnchecked,
    &checkers::ptr_from_raw_parts::PtrFromRawParts,
    &checkers::clone_to_uninit_call::CloneToUninitCall,
    &checkers::layout_for_value_raw::LayoutForValueRaw,
    &checkers::trusted_len_impl::TrustedLenImpl,
    &checkers::trusted_step_impl::TrustedStepImpl,
    &checkers::allocator_impl::AllocatorImpl,
    &checkers::unsafe_fn_ptr::UnsafeFnPtr,
    &checkers::slice_chunks_unchecked::SliceChunksUnchecked,
    &checkers::split_at_unchecked::SplitAtUnchecked,
    &checkers::slice_disjoint_unchecked::SliceDisjointUnchecked,
    &checkers::slice_swap_unchecked::SliceSwapUnchecked,
    &checkers::downcast_unchecked::DowncastUnchecked,
    &checkers::borrowed_cursor_advance::BorrowedCursorAdvance,
    &checkers::env_set_var::EnvSetVar,
    &checkers::ptr_swap::PtrSwap,
    &checkers::mem_size_of_val_raw::MemSizeOfValRaw,
    &checkers::allocator_methods::AllocatorMethods,
    &checkers::arch_intrinsic::ArchIntrinsic,
    &checkers::simd_unchecked::SimdUnchecked,
    &checkers::refcell_unsafe::RefCellUnsafe,
    &checkers::ascii_unchecked::AsciiUnchecked,
    &checkers::unsafe_pinned::UnsafePinned,
    &checkers::target_feature_call::TargetFeatureCall,
    &checkers::ptr_as_ref_unchecked::PtrAsRefUnchecked,
    &checkers::unsafecell_access::UnsafeCellAccess,
    &checkers::btree_cursor_unchecked::BTreeCursorUnchecked,
    &checkers::naked_fn::NakedFn,
    &checkers::hashmap_disjoint_unchecked::HashMapDisjointUnchecked,
    &checkers::arc_get_mut_unchecked::ArcGetMutUnchecked,
    &checkers::binary_heap_unsafe::BinaryHeapUnsafe,
    &checkers::arc_strong_count::ArcStrongCount,
    &checkers::cstring_from_vec_unchecked::CStringFromVecUnchecked,
    &checkers::fast_float_arith::FastFloatArith,
    &checkers::ctlz_nonzero::CtlzNonzero,
    &checkers::va_list::VaListNextArg,
    &checkers::volatile_intrinsics::VolatileIntrinsics,
    &checkers::step_unchecked::StepUnchecked,
    &checkers::atomic_ptr_arith::AtomicPtrArith,
    &checkers::lock_api_unsafe::LockApiUnsafe,
    &checkers::memmap_unsafe::MemmapUnsafe,
    &checkers::mutex_assume_poisoned::MutexAssumeUnpoisoned,
    &checkers::bytes_buf::BytesBuf,
    &checkers::crossbeam_epoch::CrossbeamEpoch,
    &checkers::push_unchecked::PushUnchecked,
    &checkers::ndarray_unchecked::NdarrayUnchecked,
    &checkers::hashbrown_raw::HashbrownRaw,
    &checkers::smallvec_unchecked::SmallVecUnchecked,
    &checkers::rkyv_unchecked::RkyvUnchecked,
    &checkers::parking_lot_core_park::ParkingLotCorePark,
    &checkers::nix_mman::NixMman,
    &checkers::heapless_unchecked::HeaplessUnchecked,
    &checkers::not_nan_unchecked::NotNanUnchecked,
    &checkers::nix_fork::NixFork,
    &checkers::spin_unsafe::SpinUnsafe,
    &checkers::triomphe_unchecked::TriompheUnchecked,
    &checkers::nalgebra_unchecked::NalgebraUnchecked,
    &checkers::zerocopy_unchecked::ZerocopyUnchecked,
    &checkers::regex_automata_unchecked::RegexAutomataUnchecked,
    &checkers::bitvec_unchecked::BitvecUnchecked,
    &checkers::matrixmultiply_unchecked::MatrixmultiplyUnchecked,
    &checkers::hashbrown_map_unchecked::HashbrownMapUnchecked,
    &checkers::slab_unchecked::SlabUnchecked,
    &checkers::slotmap_unchecked::SlotmapUnchecked,
    &checkers::psm_unsafe::PsmUnsafe,
    &checkers::arrayvec_unchecked::ArrayvecUnchecked,
    &checkers::signal_hook_unsafe::SignalHookUnsafe,
    &checkers::socket2_unsafe::Socket2Unsafe,
    &checkers::bytemuck_unsafe_impl::BytemuckUnsafeImpl,
    &checkers::zerovec_unchecked::ZerovecUnchecked,
    &checkers::log_racy::LogRacy,
    &checkers::yoke_replace_cart::YokeReplaceCart,
    &checkers::http_unchecked::HttpUnchecked,
    &checkers::time_tz_unchecked::TimeTzUnchecked,
    &checkers::rustix_unsafe::RustixUnsafe,
    &checkers::typed_arena_unchecked::TypedArenaUnchecked,
];

static FLOW_CHECKERS: &[&(dyn FlowChecker + Sync)] = &[
    &checkers::flow::ownership::OwnershipProtocol,
    &checkers::flow::epoch_guard::EpochGuard,
    &checkers::flow::lock_state::LockState,
];

pub fn debug_print_all_paths(tcx: TyCtxt<'_>) {
    use rustc_middle::mir::TerminatorKind;
    for &local_def_id in tcx.mir_keys(()).iter() {
        let def_id = local_def_id.to_def_id();
        match tcx.def_kind(def_id) {
            DefKind::Fn | DefKind::AssocFn | DefKind::Closure | DefKind::SyntheticCoroutineBody => {}
            _ => continue,
        }
        let body = tcx.optimized_mir(def_id);
        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((callee_def_id, _)) = func.const_fn_def() else { continue };
            let path = tcx.def_path_str(callee_def_id);
            eprintln!("CALL: {path}");
        }
    }
}

pub fn run_checks(tcx: TyCtxt<'_>) -> Vec<Finding> {
    let name = tcx.crate_name(LOCAL_CRATE);
    eprintln!("san: analyzing crate `{name}`");

    let mut findings = Vec::new();

    // Crate-level checks (HIR, impl blocks, etc.)
    for checker in CHECKERS {
        findings.extend(checker.check_crate(tcx));
    }

    // Per-body MIR checks — functions and closures only.
    // Constants/statics use mir_for_ctfe, not optimized_mir; skip them here.
    for &local_def_id in tcx.mir_keys(()).iter() {
        let def_id = local_def_id.to_def_id();
        match tcx.def_kind(def_id) {
            DefKind::Fn | DefKind::AssocFn | DefKind::Closure | DefKind::SyntheticCoroutineBody => {}
            _ => continue,
        }
        let body = tcx.optimized_mir(def_id);
        for checker in CHECKERS {
            findings.extend(checker.check(tcx, body));
        }
        let flow = analysis::compute_flow(tcx, body);
        for checker in FLOW_CHECKERS {
            findings.extend(checker.check_flow(tcx, body, &flow));
        }
    }

    findings
}
