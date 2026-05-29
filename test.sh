#!/usr/bin/env bash
# Smoke-test runner: builds each fixture with san-driver and checks that
# the expected [san::rule_id] warning appears at least once.
# Usage: ./test.sh [fixture_name ...]  (no args = run all)
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
DRIVER="$REPO/target/debug/san-driver"
FIXTURES_DIR="$REPO/fixtures"

# Map fixture directory name → expected rule id(s) (space-separated).
# Add a row here whenever a new checker gains a fixture.
declare -A EXPECTED=(
    [arc_from_raw]="arc_from_raw"
    [global_alloc_impl]="global_alloc_impl"
    [assume_init]="assume_init"
    [atomic_from_ptr]="atomic_from_ptr"
    [box_from_raw]="box_from_raw"
    [char_from_u32_unchecked]="char_from_u32_unchecked"
    [cstr_from_ptr]="cstr_from_ptr"
    [cstring_as_ptr]="cstring_as_ptr"
    [hint_assert_unchecked]="hint_assert_unchecked"
    [inline_asm]="inline_asm"
    [into_raw]="into_raw"
    [layout_unchecked]="layout_unchecked"
    [manually_drop]="manually_drop"
    [mem_forget]="mem_forget"
    [mem_transmute]="mem_transmute"
    [mem_transmute_copy]="mem_transmute_copy"
    [mem_uninitialized]="mem_uninitialized"
    [mem_zeroed_generic]="mem_zeroed_generic"
    [missing_send_sync_bounds]="missing_send_sync_bounds"
    [nonnull_deref]="nonnull_deref"
    [nonnull_new_unchecked]="nonnull_new_unchecked"
    [nonzero_new_unchecked]="nonzero_new_unchecked"
    [osstr_encoded_bytes]="osstr_encoded_bytes"
    [pin_new_unchecked]="pin_new_unchecked"
    [ptr_arith]="ptr_arith"
    [ptr_as_ref]="ptr_as_ref"
    [pre_exec]="pre_exec"
    [ptr_copy]="ptr_copy"
    [ptr_provenance]="ptr_provenance"
    [ptr_drop_in_place]="ptr_drop_in_place"
    [ptr_read]="ptr_read"
    [ptr_write]="ptr_write"
    [raw_ptr_deref]="raw_ptr_deref"
    [raw_allocator]="raw_allocator"
    [raw_fd]="raw_fd"
    [slice_align_to]="slice_align_to"
    [slice_from_raw_parts]="slice_from_raw_parts"
    [slice_get_unchecked]="slice_get_unchecked"
    [static_mut]="static_mut"
    [str_from_utf8_unchecked]="str_from_utf8_unchecked"
    [str_mutation]="str_mutation"
    [thread_spawn_unchecked]="thread_spawn_unchecked"
    [unchecked_int_arith]="unchecked_int_arith"
    [union_field]="union_field"
    [unsafecell_get]="unsafecell_get"
    [unreachable_unchecked]="unreachable_unchecked"
    [unwrap_unchecked]="unwrap_unchecked"
    [vec_from_raw_parts]="vec_from_raw_parts"
    [vec_set_len]="vec_set_len"
    [waker_from_raw]="waker_from_raw"
    [cstr_from_bytes_unchecked]="cstr_from_bytes_unchecked"
    [cstring_from_raw]="cstring_from_raw"
    [foreign_fn]="foreign_fn"
    [string_from_raw_parts]="string_from_raw_parts"
    [float_to_int_unchecked]="float_to_int_unchecked"
    [ptr_from_raw_parts]="ptr_from_raw_parts"
    [clone_to_uninit_call]="clone_to_uninit_call"
    [clone_to_uninit_impl]="clone_to_uninit_impl"
    [layout_for_value_raw]="layout_for_value_raw"
    [trusted_len_impl]="trusted_len_impl"
    [trusted_step_impl]="trusted_step_impl"
    [allocator_impl]="allocator_impl"
    [unsafe_fn_ptr]="unsafe_fn_ptr"
    [unsafe_fn_call]="unsafe_fn_call"
    [use_after_free]="use_after_free"
    [cross_fn_double_free]="use_after_free"
    [xcrate_buffer_uaf]="use_after_free"
    [fnptr_uaf]="use_after_free"
    [slice_chunks_unchecked]="slice_chunks_unchecked"
    [split_at_unchecked]="split_at_unchecked"
    [slice_disjoint_unchecked]="slice_disjoint_unchecked"
    [slice_swap_unchecked]="slice_swap_unchecked"
    [ascii_unchecked]="ascii_unchecked"
    [unsafe_pinned]="unsafe_pinned"
    [target_feature_call]="target_feature_call"
    [downcast_unchecked]="downcast_unchecked"
    [borrowed_cursor_advance]="borrowed_cursor_advance"
    [env_set_var]="env_set_var"
    [ptr_swap]="ptr_swap"
    [mem_size_of_val_raw]="mem_size_of_val_raw"
    [allocator_methods]="allocator_methods"
    [arch_intrinsic]="arch_intrinsic"
    [simd_unchecked]="simd_unchecked"
    [refcell_unsafe]="refcell_unsafe"
    [ptr_as_ref_unchecked]="ptr_as_ref_unchecked"
    [unsafecell_access]="unsafecell_access"
    [btree_cursor_unchecked]="btree_cursor_unchecked"
    [naked_fn]="naked_fn"
    [hashmap_disjoint_unchecked]="hashmap_disjoint_unchecked"
    [arc_get_mut_unchecked]="arc_get_mut_unchecked"
    [binary_heap_unsafe]="binary_heap_unsafe"
    [arc_strong_count]="arc_strong_count"
    [cstring_from_vec_unchecked]="cstring_from_vec_unchecked"
    [fast_float_arith]="fast_float_arith"
    [ctlz_nonzero]="ctlz_nonzero"
    [va_list]="va_list"
    [volatile_intrinsics]="volatile_intrinsics"
    [step_unchecked]="step_unchecked"
    [atomic_ptr_arith]="atomic_ptr_arith"
    [lock_api_unsafe]="lock_api_unsafe"
    [memmap_unsafe]="memmap_unsafe"
    [mutex_assume_poisoned]="mutex_clear_poison"
    [bytes_buf]="bytes_buf"
    [crossbeam_epoch]="crossbeam_epoch"
    [push_unchecked]="push_unchecked"
    [ndarray_unchecked]="ndarray_unchecked"
    [hashbrown_raw]="hashbrown_raw"
    [smallvec_unchecked]="smallvec_unchecked"
    [rkyv_unchecked]="rkyv_unchecked"
    [parking_lot_core_park]="parking_lot_core_park"
    [nix_mman]="nix_mman"
    [heapless_unchecked]="heapless_unchecked"
    [not_nan_unchecked]="not_nan_unchecked"
    [nix_fork]="nix_fork"
    [spin_unsafe]="spin_unsafe"
    [triomphe_unchecked]="triomphe_unchecked"
    [nalgebra_unchecked]="nalgebra_unchecked"
    [zerocopy_unchecked]="zerocopy_unchecked"
    [regex_automata_unchecked]="regex_automata_unchecked"
    [bitvec_unchecked]="bitvec_unchecked"
    [matrixmultiply_unchecked]="matrixmultiply_unchecked"
    [hashbrown_map_unchecked]="hashbrown_map_unchecked"
    [slab_unchecked]="slab_unchecked"
    [slotmap_unchecked]="slotmap_unchecked"
    [psm_unsafe]="psm_unsafe"
    [arrayvec_unchecked]="arrayvec_unchecked"
    [signal_hook_unsafe]="signal_hook_unsafe"
    [socket2_unsafe]="socket2_unsafe"
    [bytemuck_unsafe_impl]="bytemuck_unsafe_impl"
    [zerovec_unchecked]="zerovec_unchecked"
    [log_racy]="log_racy"
    [yoke_replace_cart]="yoke_replace_cart"
    [http_unchecked]="http_unchecked"
    [time_tz_unchecked]="time_tz_unchecked"
    [rustix_unsafe]="rustix_unsafe"
    [typed_arena_unchecked]="typed_arena_unchecked"
    # flow-sensitive checkers
    [flow_ownership]="ownership_double_free"
    [flow_ownership_leak]="ownership_leak"
    # hello and no_findings_safe_code are negative tests — must produce zero findings
    [hello]=""
    [no_findings_safe_code]=""
)

pass=0
fail=0
skip=0

inc() { eval "$1=$(( ${!1} + 1 ))"; }

run_fixture() {
    local name="$1"
    local dir="$FIXTURES_DIR/$name"
    local expected="${EXPECTED[$name]-UNKNOWN}"

    if [[ "$expected" == "UNKNOWN" ]]; then
        echo "  SKIP  $name  (no entry in EXPECTED map)"
        inc skip
        return
    fi

    # Clean target to force a fresh analysis (cargo caches compiled output).
    cargo clean --manifest-path "$dir/Cargo.toml" -q 2>/dev/null || true

    local output
    output=$(RUSTC_WORKSPACE_WRAPPER="$DRIVER" \
        cargo build --manifest-path "$dir/Cargo.toml" 2>&1) || true

    if [[ -z "$expected" ]]; then
        # Fixture is expected to produce zero san findings.
        if echo "$output" | grep -q "\[san::"; then
            echo "  FAIL  $name  (unexpected san warning)"
            echo "$output" | grep "\[san::" | head -3 | sed 's/^/    /'
            inc fail
        else
            echo "  PASS  $name"
            inc pass
        fi
        return
    fi

    local all_ok=true
    for rule in $expected; do
        if echo "$output" | grep -qF "[san::${rule}]"; then
            : # found
        else
            echo "  FAIL  $name  (missing [san::${rule}])"
            all_ok=false
        fi
    done

    if $all_ok; then
        echo "  PASS  $name"
        inc pass
    else
        inc fail
    fi
}

# Build san-driver first.
echo "Building san-driver..."
cargo build --manifest-path "$REPO/Cargo.toml" -q

echo ""
echo "Running fixture tests..."

if [[ $# -gt 0 ]]; then
    for name in "$@"; do
        run_fixture "$name"
    done
else
    for dir in "$FIXTURES_DIR"/*/; do
        name="$(basename "$dir")"
        run_fixture "$name"
    done
fi

echo ""
echo "Results: $pass passed, $fail failed, $skip skipped"
[[ $fail -eq 0 ]]
