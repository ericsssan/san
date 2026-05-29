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

/// Unified checker trait. Every checker receives pre-computed flow results so
/// it can optionally suppress findings that flow analysis shows are safe.
/// `check_crate` is for whole-crate HIR passes (impl-block analysis, etc.).
pub trait Checker: Send + Sync {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &mir::Body<'tcx>,
        flow: &analysis::FlowResults,
    ) -> Vec<Finding> {
        let _ = (tcx, body, flow);
        Vec::new()
    }

    fn check_crate<'tcx>(&self, tcx: TyCtxt<'tcx>) -> Vec<Finding> {
        let _ = tcx;
        Vec::new()
    }
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
    &checkers::raw_ptr_deref::RawPtrDeref,
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
    &checkers::unsafe_fn_call::UnsafeFnCall,
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
    // Flow-sensitive checkers (use flow results for precise detection).
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

/// Well-known std accessors that hand back a pointer into `self`'s owned
/// allocation (`Vec`/slice/`String`). Used to seed a cross-crate alias-of-param
/// effect that the bounded summary computation cannot derive through std's
/// deeply-nested internals.
fn is_owned_buffer_accessor(path: &str) -> bool {
    (path.ends_with("::as_mut_ptr") || path.ends_with("::as_ptr"))
        && (path.contains("vec::Vec") || path.contains("[T]") || path.contains("string::String"))
}

pub fn run_checks(tcx: TyCtxt<'_>) -> Vec<Finding> {
    let name = tcx.crate_name(LOCAL_CRATE);
    eprintln!("san: analyzing crate `{name}`");

    let mut findings = Vec::new();

    // Collect all local fn DefIds for reuse across passes.
    let local_fns: Vec<_> = tcx
        .mir_keys(())
        .iter()
        .filter_map(|&id| {
            let def_id = id.to_def_id();
            matches!(
                tcx.def_kind(def_id),
                DefKind::Fn
                    | DefKind::AssocFn
                    | DefKind::Closure
                    | DefKind::SyntheticCoroutineBody
            )
            .then_some(def_id)
        })
        .collect();

    // Cross-crate summaries: also summarize external callees whose MIR is
    // exported (generic / `#[inline]` fns — std ships MIR for these). This lets
    // a consume / alias-of-param effect resolve across a crate boundary, e.g. a
    // dependency's deallocator or `Vec::as_mut_ptr` handing back self's buffer.
    // Bounded by breadth (depth from local code) and a hard cap so we never try
    // to drag in all of std.
    const MAX_EXTERNAL_DEPTH: usize = 2;
    const MAX_EXTERNAL_FNS: usize = 600;
    let mut to_summarize: Vec<rustc_hir::def_id::DefId> = local_fns.clone();
    {
        use rustc_middle::mir::TerminatorKind;
        let mut in_set: std::collections::HashSet<_> = local_fns.iter().copied().collect();
        let mut frontier = local_fns.clone();
        let mut ext_count = 0usize;
        for _ in 0..MAX_EXTERNAL_DEPTH {
            if ext_count >= MAX_EXTERNAL_FNS {
                break;
            }
            let mut next = Vec::new();
            for &def_id in &frontier {
                for bb in tcx.optimized_mir(def_id).basic_blocks.iter() {
                    let Some(term) = &bb.terminator else { continue };
                    let TerminatorKind::Call { func, .. } = &term.kind else { continue };
                    let Some((callee, _)) = func.const_fn_def() else { continue };
                    if in_set.contains(&callee) || ext_count >= MAX_EXTERNAL_FNS {
                        continue;
                    }
                    if matches!(tcx.def_kind(callee), DefKind::Fn | DefKind::AssocFn)
                        && tcx.is_mir_available(callee)
                    {
                        in_set.insert(callee);
                        to_summarize.push(callee);
                        next.push(callee);
                        ext_count += 1;
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
    }

    // Interprocedural summary computation by chaotic iteration to a fixpoint.
    // Each round recomputes every function's summary against the previous
    // round's snapshot, so effects propagate one extra call level per round:
    // round 1 resolves leaves, round 2 their callers, and so on. A deep
    // consuming chain `a -> b -> c -> Box::from_raw` needs as many rounds as it
    // is deep, which the fixed 2-pass scheme could not reach. We iterate until
    // the summary map stops changing, capped to bound cost on large crates.
    const MAX_SUMMARY_ROUNDS: usize = 8;
    let mut summaries = analysis::SummaryMap::new();
    for _ in 0..MAX_SUMMARY_ROUNDS {
        let snap = summaries.clone();
        for &def_id in &to_summarize {
            let body = tcx.optimized_mir(def_id);
            let flow = analysis::compute_flow_for_summary(tcx, body, &snap);
            let mut s = analysis::summary::extract_summary(tcx, body, &flow);
            // For EXTERNAL functions we trust only the structurally-safe
            // `returns_alias_of_param` effect. The consume (`Reconstituted`) and
            // `returns_raw_owned` effects are unsound to propagate across a crate
            // boundary blindly: an external fn that internally calls `from_raw`
            // (e.g. `Arc::decrement_strong_count`) does NOT necessarily consume
            // the caller's pointer — refcount semantics keep it valid — so
            // trusting that would produce false double-frees in correct code.
            if !def_id.is_local() {
                s.param_effects.clear();
                s.returns_raw_owned = false;
                // Curated knowledge for std's owned-buffer accessors, whose real
                // provenance chain (Vec -> RawVec -> Unique -> NonNull) is deeper
                // than the summary depth cap: they return a pointer into `self`'s
                // owned allocation, so the result aliases parameter 0.
                if is_owned_buffer_accessor(&tcx.def_path_str(def_id)) {
                    s.returns_alias_of_param = Some(0);
                }
            }
            if !s.param_effects.is_empty()
                || s.returns_raw_owned
                || s.returns_alias_of_param.is_some()
                || s.reallocs_param.is_some()
            {
                summaries.insert(def_id, s);
            } else {
                summaries.remove(&def_id);
            }
        }
        if summaries == snap {
            break;
        }
    }

    // Crate-level (HIR) checks — flow is not applicable here.
    for checker in CHECKERS {
        findings.extend(checker.check_crate(tcx));
    }

    // Per-body MIR checks. Flow is computed once per body and passed to every
    // checker so they can optionally suppress findings that flow shows are safe.
    // Wrap the converged summaries in an `Rc` so each `FlowResults` can carry
    // them cheaply to checkers that need interprocedural effects.
    let summaries = std::rc::Rc::new(summaries);
    for &def_id in &local_fns {
        let body = tcx.optimized_mir(def_id);
        let flow = analysis::compute_flow(tcx, body, &summaries);
        for checker in CHECKERS {
            findings.extend(checker.check(tcx, body, &flow));
        }
    }

    // Deduplicate by (rule_id, source position). A single source location is
    // frequently reached by many MIR bodies — e.g. a `get_unchecked_mut` inside
    // a `macro_rules!` body is one source span shared by every macro expansion,
    // and generic helpers are analyzed once per monomorphization. We key on the
    // span's byte range rather than the `Span` itself because each macro
    // expansion carries a distinct `SyntaxContext`: the spans render to the same
    // file:line:col but compare unequal. Byte positions are global within the
    // crate's source map, so (lo, hi) identifies a unique source location.
    // Collapsing duplicates removes no distinct finding — no false-negative risk.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.rule_id, f.span.lo(), f.span.hi())));

    // `unsafe_fn_call` is a backstop: it should fire only where no more-specific
    // checker already spoke. Drop any of its findings whose call-site span
    // overlaps a finding from another rule (e.g. the `NonNull::as_mut` deref on
    // the same `L::pointers(p).as_mut()` line). Spans overlap when their byte
    // ranges intersect; a method-call span typically contains its receiver call.
    let mut covered: Vec<(rustc_span::BytePos, rustc_span::BytePos)> = findings
        .iter()
        .filter(|f| f.rule_id != "unsafe_fn_call")
        .map(|f| (f.span.lo(), f.span.hi()))
        .collect();
    covered.sort();
    findings.retain(|f| {
        if f.rule_id != "unsafe_fn_call" {
            return true;
        }
        let (lo, hi) = (f.span.lo(), f.span.hi());
        // Keep only if no other-rule span intersects [lo, hi).
        !covered.iter().any(|&(clo, chi)| clo < hi && lo < chi)
    });

    findings
}
