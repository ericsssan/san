# san

**A deep static analyzer for `unsafe` Rust.**

`san` (Static ANalyzer) hunts for soundness and undefined-behavior bugs in the
places the compiler can't help you: `unsafe` blocks. It plugs into the compiler
as a `rustc` driver, runs **MIR-level dataflow and typestate analysis** over your
crate, and reports the unsound `unsafe` usage that borrow-checking and Miri don't
catch statically.

132 checkers, spanning the standard library's `unsafe` surface and the most
common `unsafe`-heavy crates in the ecosystem.

> ⚠️ Status: early, actively developed (v0.1). Expect rough edges and the
> occasional false positive — see [Caveats](#caveats).

---

## Why

`unsafe` is where Rust's guarantees stop and the programmer's invariants begin.
The borrow checker steps aside; Miri only catches UB on code paths you actually
execute. `san` aims for the gap in between — **statically** flagging `unsafe`
operations whose safety preconditions look unmet, so the bug surfaces at analysis
time instead of in production.

## How it works

`san` is a [`rustc_private`](https://doc.rust-lang.org/nightly/nightly-rustc/)
driver — it reuses the real compiler front-end, so it sees exactly the same
`HIR`/`MIR` rustc does, with full type information.

```
cargo-san      cargo subcommand shim  →  forwards args
  └─ san-driver   rustc driver: runs the compiler, hands MIR to…
       └─ san     the analysis library: dataflow + typestate + 132 checkers
```

The analysis engine (`crates/san/src/analysis/`) is a proper dataflow framework:
`dataflow` fixpoint iteration, a `typestate` lattice, `transfer` functions,
function `summary` caching, and `precond` tracking — so checkers reason about
*flow-proven* facts (this pointer is dangling here, this field is uninitialized
on this path) rather than syntactic patterns.

## What it catches

The 132 checkers group into families:

- **Uninitialized memory** — `MaybeUninit::assume_init` on partially-init values,
  `mem::uninitialized`, `mem::zeroed` on non-zeroable types, sub-field init tracking
- **Raw-pointer ownership** — `Box::from_raw` / `Arc::from_raw` / `CString::from_raw`
  misuse, double-free and use-after-`into_raw`, `from_raw_parts` bounds
- **Transmute & casts** — `mem::transmute` / `transmute_copy` size & validity mismatches,
  `cast_away_const`, `float_to_int_unchecked`, `char::from_u32_unchecked`
- **Unchecked bounds** — the `*_unchecked` family: `get_unchecked`, `str`/`ascii`,
  `arrayvec`, `bitvec`, `heapless`, `hashbrown` raw entry, …
- **Allocator soundness** — `GlobalAlloc`/`Allocator` impl invariants,
  `alloc_size_overflow`, `Layout::*_unchecked`
- **Concurrency & atomics** — `AtomicPtr` from raw, atomic pointer arithmetic,
  `Arc::get_mut_unchecked`, missing `Send`/`Sync` bounds, poisoned-lock assumptions
- **FFI, inline asm & intrinsics** — foreign-fn signatures, `asm!`, arch intrinsics,
  `assert_unchecked`, `ctlz_nonzero`
- **Lifetimes & drop** — `ManuallyDrop` / `mem::forget` leaks, `size_of_val_raw`

Plus dedicated checkers for popular `unsafe`-heavy crates: `bytemuck`, `crossbeam`,
`smallvec`, `bytes`, `memmap`, `lock_api`, `matrixmultiply`, and more.

## Install & run

`san` uses compiler internals, so it requires the pinned nightly toolchain
declared in [`rust-toolchain.toml`](./rust-toolchain.toml) (`rustc-dev` +
`rust-src` components, selected automatically by `rustup` when you build).

```sh
# build the driver and cargo subcommand
cargo build --release

# analyze a crate (from that crate's directory)
cargo san
```

`cargo san` compiles the target crate through `san-driver` and prints findings as
`severity · rule_id · message` with the source location — for example, an
`Error`-level `box_from_raw` finding pointing at the line where a non-`Box`-allocated
pointer is handed to `Box::from_raw`. Severities are **Error / Warning / Info**.

## Layout

```
crates/
  cargo-san/     `cargo san` subcommand entry point
  san-driver/    rustc driver — runs the compiler, invokes the analysis
  san/           analysis engine + the 132 checkers
    src/analysis/   dataflow, typestate, transfer, summaries, preconditions
    src/checkers/   one module per rule
fixtures/        183 crates exercising the checkers (the test corpus)
```

## Caveats

- **Nightly-only.** Built on unstable `rustc_private` APIs and pinned to a specific
  nightly; it will need updating as those internals drift.
- **Early-stage.** Coverage is broad but depth varies by checker; false positives
  happen. Treat findings as leads to investigate, not verdicts.

## License

[MIT](./LICENSE)
