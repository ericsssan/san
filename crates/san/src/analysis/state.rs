use std::collections::{BTreeSet, HashMap, HashSet};

use rustc_hir::def_id::DefId;
use rustc_middle::mir::Local;

use crate::analysis::object::{HeapMap, HeapState, InitState, ObjectId};
use crate::analysis::typestate::{ProtocolId, ProtocolState, TypestateMap};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BlockState {
    pub heap: HeapMap,
    /// Each Local may point to a set of abstract objects (join = union).
    pub points_to: HashMap<Local, BTreeSet<ObjectId>>,
    /// A Local may hold multiple protocol instances at a merge point (join = union of sets).
    pub local_proto: HashMap<Local, BTreeSet<ProtocolId>>,
    pub typestate: TypestateMap,
    /// Set when `mem::forget` is called on a local that has no tracked ProtocolId —
    /// typically a guard received as a function parameter. Used by the lock-state
    /// checker to avoid false positives when force_unlock follows a parameter-guard forget.
    pub untracked_forget_seen: bool,
    /// Tracks whether each `MaybeUninit` local is provably initialized.
    /// Absence from the map means `Unknown`. Join is per-key: Initialized ⊓ Unknown = Unknown.
    /// Keys present in only one branch are inserted with `Unknown` conservatively — actually
    /// for keys only in `other`, we propagate them as-is (they weren't observed on `self`'s
    /// path, so we union in the new info with `changed = true`).
    pub init: HashMap<Local, InitState>,
    /// Locals that are known to have had bytes written to a `BufMut` region before any
    /// `advance_mut` call. Join is INTERSECTION: a local is only "written" if ALL predecessor
    /// paths wrote to it (so we only suppress `advance_mut` when we are certain).
    pub buf_written: HashSet<Local>,
    /// cmp_result_local → lhs_local: this comparison-result local holds (lhs < something).
    /// Used for bounds range tracking. Join is UNION.
    pub lt_facts: HashMap<Local, Local>,
    /// cmp_result_local → lhs_local: this comparison-result local holds (lhs >= something).
    /// Used for bounds range tracking. Join is UNION.
    pub ge_facts: HashMap<Local, Local>,
    /// cmp_result_local → lhs_local: this comparison-result local holds (lhs <= something).
    /// Used for bounds range tracking. Join is UNION.
    pub le_facts: HashMap<Local, Local>,
    /// cmp_result_local → lhs_local: this comparison-result local holds (lhs > something).
    /// Used for bounds range tracking. Join is UNION.
    pub gt_facts: HashMap<Local, Local>,
    /// Locals proven to be < some length (via Assert terminator). Join is INTERSECTION.
    pub bounded: HashSet<Local>,
    /// Locals proven to be <= some length (via Assert terminator). Join is INTERSECTION.
    pub bounded_or_eq: HashSet<Local>,
    /// pointer-local → set of *owner* locals whose interior allocation this
    /// pointer aliases. Established when a pointer is loaded from the interior of
    /// an owner (typically `&mut self`), directly or via a callee summarised as
    /// returning a pointer into a parameter. BROKEN by any write to the owner
    /// (the field may have been reassigned). Join is UNION (may-alias): if the
    /// pointer aliases an owner on *any* incoming path, freeing it there can
    /// leave that owner dangling. Used to detect double-free / UAF where the
    /// second free happens later through the owner (e.g. its `Drop`).
    pub owner_alias: HashMap<Local, BTreeSet<Local>>,
    /// fn-pointer local → the concrete fn it was reified from (`foo as fn(..)`).
    /// Lets an *indirect* call through such a pointer be resolved to a known
    /// target and its summary applied. Join keeps a mapping only if all paths
    /// agree on the target (must-resolve), so resolution stays conservative.
    pub fn_ptr_targets: HashMap<Local, DefId>,
    /// Parameter locals whose backing buffer was reallocated somewhere in this
    /// body (a realloc method called on a value aliasing the parameter). Used to
    /// derive a `reallocs_param` summary so wrapper methods like
    /// `BitVec::into_boxed_slice` propagate the realloc effect. Join is UNION.
    pub realloced_params: BTreeSet<Local>,
    /// borrow-temp → base local of the borrowed place: records `dst = &(*base)`
    /// / `dst = &base` so a `len`/`capacity` call whose receiver is a reborrow
    /// can be attributed back to the underlying collection. Join is UNION.
    pub ref_base: HashMap<Local, Local>,
    /// result-of-`len()`-call → collection local. Join is UNION.
    pub len_of: HashMap<Local, Local>,
    /// result-of-`capacity()`-call → collection local. Join is UNION.
    pub cap_of: HashMap<Local, Local>,
    /// comparison-result local → collection local, where the collection is proven
    /// to have spare capacity (`len < capacity`) when the comparison is TRUE
    /// (e.g. `Lt(len(C), cap(C))`). Drained on the taken `SwitchInt` edge. UNION.
    pub spare_if_true: HashMap<Local, Local>,
    /// Like `spare_if_true` but the collection has spare capacity when the
    /// comparison is FALSE (e.g. early-return `if len(C) >= cap(C) { return }`).
    pub spare_if_false: HashMap<Local, Local>,
    /// Collections proven to currently have spare capacity (`len < capacity`) on
    /// ALL paths reaching here. Set on the taken `SwitchInt` edge of a
    /// len/capacity guard; cleared when the collection is passed to any call (it
    /// may mutate the length). Join is INTERSECTION (like `bounded`).
    pub has_spare: HashSet<Local>,
    /// comparison-result local → collection local proven to be exactly full
    /// (`len == capacity`) when the comparison is TRUE (e.g. `Eq(len(C), cap(C))`).
    /// Drained on the taken `SwitchInt` edge. UNION.
    pub full_if_true: HashMap<Local, Local>,
    /// Like `full_if_true` but the collection is full when the comparison is
    /// FALSE (e.g. early-return `if len(C) != cap(C) { return }`).
    pub full_if_false: HashMap<Local, Local>,
    /// Collections proven to be exactly full (`len == capacity`) on ALL paths.
    /// Mirror of `has_spare` for the `into_inner_unchecked`-style APIs whose
    /// safety condition is "completely full". Join is INTERSECTION.
    pub is_full: HashSet<Local>,

    // ── value-range / scalar-property domain ───────────────────────────────
    // These fields power suppression for NonZero, NotNan, char-from-u32 etc.

    /// Locals proven ≠ 0 on ALL reaching paths (e.g. `if n != 0`). Join =
    /// INTERSECTION.  Derived from `nonzero_if_true/false` at `SwitchInt` edges,
    /// and from `const_lower ≥ 1`.
    pub nonzero: HashSet<Local>,
    /// cmp-result → local: cmp = `local != 0` (or `local > 0` etc.).
    /// True edge of the SwitchInt → nonzero. Join = UNION.
    pub nonzero_if_true: HashMap<Local, Local>,
    /// cmp-result → local: cmp = `local == 0`.
    /// False edge of the SwitchInt → nonzero. Join = UNION.
    pub nonzero_if_false: HashMap<Local, Local>,

    /// Locals proven not-NaN (is_finite) on ALL reaching paths. Join = INTERSECTION.
    pub finite: HashSet<Local>,
    /// cmp-result → float-local: cmp = `is_finite(local)`.
    /// True edge → finite. Join = UNION.
    pub finite_if_true: HashMap<Local, Local>,
    /// cmp-result → float-local: cmp = `is_nan(local)`.
    /// False edge → finite. Join = UNION.
    pub nan_if_true: HashMap<Local, Local>,

    /// Proven constant upper bound: `local ≤ bound`. Join = INTERSECTION of
    /// keys, MAX of values (weaker bound holds on all paths).
    pub const_upper: HashMap<Local, u64>,
    /// Proven constant lower bound: `local ≥ bound`. Join = INTERSECTION of
    /// keys, MIN of values (weaker bound holds on all paths).
    pub const_lower: HashMap<Local, u64>,
    /// cmp-result → (local, k): cmp = `local < k`. Drain into `const_upper`
    /// on the true SwitchInt edge. Join = UNION.
    pub const_lt: HashMap<Local, (Local, u64)>,
    /// cmp-result → (local, k): cmp = `local ≤ k`. Join = UNION.
    pub const_le: HashMap<Local, (Local, u64)>,
    /// cmp-result → (local, k): cmp = `local > k`. Drain into `const_lower`
    /// on the true SwitchInt edge. Join = UNION.
    pub const_gt: HashMap<Local, (Local, u64)>,
    /// cmp-result → (local, k): cmp = `local ≥ k`. Join = UNION.
    pub const_ge: HashMap<Local, (Local, u64)>,

    // ── local-pair equality / disequality domain ───────────────────────────
    /// Canonical pairs (a.index() ≤ b.index()) proven equal on ALL reaching
    /// paths — from `Eq(a, b)` true edge or `Ne(a, b)` false edge.
    /// Drives suppression of stride-coherence checks (matrixmultiply, etc.).
    /// Join = INTERSECTION. Cleared when either local is reassigned.
    pub eq_locals: HashSet<(Local, Local)>,
    /// `dst = integer_cast(src)` → `cast_origin[dst] = src`. Lets
    /// `locals_are_eq` see through `k as isize` style conversions so that an
    /// `isize` stride argument is recognised as equal to its `usize` source.
    /// Join = UNION. Cleared when dst is reassigned.
    pub cast_origin: HashMap<Local, Local>,

    // ── local-pair disequality domain ──────────────────────────────────────
    /// `cmp_local → (a, b)`: `cmp = Ne(a, b)` where both are plain locals.
    /// True SwitchInt edge drains into `keys_are_ne`. Join = UNION.
    pub ne_pair_if_true: HashMap<Local, (Local, Local)>,
    /// `cmp_local → (a, b)`: `cmp = Eq(a, b)` where both are plain locals.
    /// False SwitchInt edge drains into `keys_are_ne`. Join = UNION.
    pub eq_pair_if_true: HashMap<Local, (Local, Local)>,
    /// Canonical pairs (a.index() ≤ b.index()) of locals proven ≠ on ALL
    /// reaching paths — from explicit `if a != b` or `if a == b { return }`.
    /// Drives suppression of `Slab::get2_unchecked_mut` when the two keys are
    /// provably disjoint. Join = INTERSECTION. Cleared when either local is
    /// reassigned.
    pub keys_are_ne: HashSet<(Local, Local)>,

    // ── multi-dimensional index domain ─────────────────────────────────────
    /// Maps an array/tuple aggregate local to the ordered list of component
    /// locals it was built from: `_idx = [i, j]` → `array_components[_idx] = [i, j]`.
    /// Only populated when ALL operands are plain (projection-free) locals.
    /// Used to decompose ndarray and simd indices into scalar components that
    /// can each be checked against `bounded`. Join = UNION.
    pub array_components: HashMap<Local, Vec<Local>>,

    // ── fd-lifecycle / I/O-safety domain ───────────────────────────────────
    /// Locals whose integer value was produced by `into_raw_fd/socket/handle`.
    /// Suppresses `from_raw_fd` for the canonical transfer pattern (safe).
    /// Join = INTERSECTION (only suppress if provable on ALL paths).
    pub fd_origin: HashSet<Local>,
    /// Locals whose raw-fd integer was already passed to `from_raw_fd/socket/
    /// handle`. A second `from_raw_*` on the same local is double-ownership.
    /// Join = UNION (escalate if consumed on ANY path).
    pub fd_consumed: HashSet<Local>,
    /// Set on any path that calls `thread::spawn` or `thread::Builder::spawn`.
    /// Used to escalate `env::set_var` when provably concurrent. Join = OR.
    pub thread_spawned: bool,
}

impl BlockState {
    /// Merge `other` into `self`. Returns `(merged, changed)`.
    pub fn join_with(&self, other: &Self) -> (Self, bool) {
        let mut result = self.clone();
        let mut changed = false;

        for (id, state) in &other.heap {
            let entry = result.heap.entry(*id).or_insert_with(|| {
                changed = true;
                state.clone()
            });
            let joined = entry.join(state);
            if joined != *entry {
                changed = true;
                *entry = joined;
            }
        }

        for (local, objs) in &other.points_to {
            let entry = result.points_to.entry(*local).or_default();
            let before = entry.len();
            for id in objs.iter().copied() {
                entry.insert(id);
            }
            if entry.len() != before {
                changed = true;
            }
        }

        // Union protocol sets — different branches may bind different guards to the same local.
        for (local, other_protos) in &other.local_proto {
            let entry = result.local_proto.entry(*local).or_default();
            let before = entry.len();
            for &pid in other_protos {
                entry.insert(pid);
            }
            if entry.len() != before {
                changed = true;
            }
        }

        for (id, state) in &other.typestate {
            let entry = result.typestate.entry(*id).or_insert_with(|| {
                changed = true;
                state.clone()
            });
            let joined = entry.join(state);
            if joined != *entry {
                changed = true;
                *entry = joined;
            }
        }

        if other.untracked_forget_seen && !result.untracked_forget_seen {
            result.untracked_forget_seen = true;
            changed = true;
        }

        // Join init maps: for keys in both, join the values; for keys only in other,
        // insert them (we gained new information about a branch's init state).
        for (local, other_init) in &other.init {
            match result.init.get(local).cloned() {
                None => {
                    // Key was absent on self's path; propagate other's value.
                    result.init.insert(*local, other_init.clone());
                    changed = true;
                }
                Some(self_init) => {
                    let joined = self_init.join(other_init);
                    if joined != self_init {
                        changed = true;
                        result.init.insert(*local, joined);
                    }
                }
            }
        }

        // Join buf_written: INTERSECTION — only keep locals written on ALL paths.
        // If self has locals that other does NOT have, they must be removed (not all paths wrote).
        let new_buf_written: HashSet<Local> = result
            .buf_written
            .iter()
            .copied()
            .filter(|l| other.buf_written.contains(l))
            .collect();
        if new_buf_written != result.buf_written {
            changed = true;
            result.buf_written = new_buf_written;
        }
        // Locals only in other are not added (intersection excludes them).

        // Join lt_facts: UNION — propagate any comparison facts from either branch.
        for (local, lhs) in &other.lt_facts {
            result.lt_facts.entry(*local).or_insert_with(|| {
                changed = true;
                *lhs
            });
        }

        // Join ge_facts: UNION — same pattern as lt_facts.
        for (local, lhs) in &other.ge_facts {
            result.ge_facts.entry(*local).or_insert_with(|| {
                changed = true;
                *lhs
            });
        }

        // Join le_facts: UNION.
        for (local, lhs) in &other.le_facts {
            result.le_facts.entry(*local).or_insert_with(|| {
                changed = true;
                *lhs
            });
        }

        // Join gt_facts: UNION.
        for (local, lhs) in &other.gt_facts {
            result.gt_facts.entry(*local).or_insert_with(|| {
                changed = true;
                *lhs
            });
        }

        // Join bounded: INTERSECTION — a local is only proven bounded on ALL paths.
        let new_bounded: HashSet<Local> = result
            .bounded
            .iter()
            .copied()
            .filter(|l| other.bounded.contains(l))
            .collect();
        if new_bounded != result.bounded {
            changed = true;
            result.bounded = new_bounded;
        }

        // Join bounded_or_eq: INTERSECTION.
        let new_bounded_or_eq: HashSet<Local> = result
            .bounded_or_eq
            .iter()
            .copied()
            .filter(|l| other.bounded_or_eq.contains(l))
            .collect();
        if new_bounded_or_eq != result.bounded_or_eq {
            changed = true;
            result.bounded_or_eq = new_bounded_or_eq;
        }

        // Join owner_alias: UNION (may-alias) — a free is unsafe if the pointer
        // aliases a live owner on ANY path reaching it.
        for (local, owners) in &other.owner_alias {
            let entry = result.owner_alias.entry(*local).or_default();
            let before = entry.len();
            for &o in owners {
                entry.insert(o);
            }
            if entry.len() != before {
                changed = true;
            }
        }

        // Join fn_ptr_targets: keep a mapping only if both paths agree on the
        // target (must-resolve); drop on conflict or absence.
        let merged: HashMap<Local, DefId> = result
            .fn_ptr_targets
            .iter()
            .filter(|(l, did)| other.fn_ptr_targets.get(l) == Some(did))
            .map(|(l, did)| (*l, *did))
            .collect();
        if merged != result.fn_ptr_targets {
            changed = true;
            result.fn_ptr_targets = merged;
        }

        // Join realloced_params: UNION.
        for &p in &other.realloced_params {
            if result.realloced_params.insert(p) {
                changed = true;
            }
        }

        // Join the spare/full-capacity fact maps: UNION (same as lt_facts).
        for (map_self, map_other) in [
            (&mut result.ref_base, &other.ref_base),
            (&mut result.len_of, &other.len_of),
            (&mut result.cap_of, &other.cap_of),
            (&mut result.spare_if_true, &other.spare_if_true),
            (&mut result.spare_if_false, &other.spare_if_false),
            (&mut result.full_if_true, &other.full_if_true),
            (&mut result.full_if_false, &other.full_if_false),
        ] {
            for (local, base) in map_other {
                map_self.entry(*local).or_insert_with(|| {
                    changed = true;
                    *base
                });
            }
        }

        // Join has_spare / is_full / nonzero / finite: INTERSECTION.
        for (set_self, set_other) in [
            (&mut result.has_spare, &other.has_spare),
            (&mut result.is_full, &other.is_full),
            (&mut result.nonzero, &other.nonzero),
            (&mut result.finite, &other.finite),
        ] {
            let new_set: HashSet<Local> =
                set_self.iter().copied().filter(|l| set_other.contains(l)).collect();
            if new_set != *set_self {
                changed = true;
                *set_self = new_set;
            }
        }

        // Join value-range aux maps: UNION (same as lt_facts).
        for (map_self, map_other) in [
            (&mut result.nonzero_if_true, &other.nonzero_if_true),
            (&mut result.nonzero_if_false, &other.nonzero_if_false),
            (&mut result.finite_if_true, &other.finite_if_true),
            (&mut result.nan_if_true, &other.nan_if_true),
        ] {
            for (local, base) in map_other {
                map_self.entry(*local).or_insert_with(|| {
                    changed = true;
                    *base
                });
            }
        }
        for (map_self, map_other) in [
            (&mut result.const_lt, &other.const_lt),
            (&mut result.const_le, &other.const_le),
            (&mut result.const_gt, &other.const_gt),
            (&mut result.const_ge, &other.const_ge),
        ] {
            for (local, pair) in map_other {
                map_self.entry(*local).or_insert_with(|| {
                    changed = true;
                    *pair
                });
            }
        }

        // Join const_upper: INTERSECTION of keys, MAX of values (weakest bound
        // that holds on ALL paths).
        let new_upper: HashMap<Local, u64> = result
            .const_upper
            .iter()
            .filter_map(|(l, &a)| {
                let b = other.const_upper.get(l)?;
                Some((*l, a.max(*b)))
            })
            .collect();
        if new_upper != result.const_upper {
            changed = true;
            result.const_upper = new_upper;
        }

        // Join const_lower: INTERSECTION of keys, MIN of values.
        let new_lower: HashMap<Local, u64> = result
            .const_lower
            .iter()
            .filter_map(|(l, &a)| {
                let b = other.const_lower.get(l)?;
                Some((*l, a.min(*b)))
            })
            .collect();
        if new_lower != result.const_lower {
            changed = true;
            result.const_lower = new_lower;
        }

        // eq_locals: INTERSECTION — only suppress if equality proven on ALL paths.
        let new_eq: HashSet<(Local, Local)> = result
            .eq_locals.iter().copied().filter(|p| other.eq_locals.contains(p)).collect();
        if new_eq != result.eq_locals { changed = true; result.eq_locals = new_eq; }

        // cast_origin: UNION — keep provenance from either branch.
        for (local, src) in &other.cast_origin {
            result.cast_origin.entry(*local).or_insert_with(|| { changed = true; *src });
        }

        // ne_pair_if_true / eq_pair_if_true: UNION.
        for (local, pair) in &other.ne_pair_if_true {
            result.ne_pair_if_true.entry(*local).or_insert_with(|| { changed = true; *pair });
        }
        for (local, pair) in &other.eq_pair_if_true {
            result.eq_pair_if_true.entry(*local).or_insert_with(|| { changed = true; *pair });
        }

        // keys_are_ne: INTERSECTION — only suppress if ≠ is proven on ALL paths.
        let new_ne: HashSet<(Local, Local)> = result
            .keys_are_ne.iter().copied().filter(|p| other.keys_are_ne.contains(p)).collect();
        if new_ne != result.keys_are_ne {
            changed = true;
            result.keys_are_ne = new_ne;
        }

        // array_components: UNION — keep decomposition info from either branch.
        for (local, comps) in &other.array_components {
            result.array_components.entry(*local).or_insert_with(|| {
                changed = true;
                comps.clone()
            });
        }

        // fd_origin: INTERSECTION — only suppress transfer pattern if proven on ALL paths.
        let new_fd_origin: HashSet<Local> = result
            .fd_origin.iter().copied().filter(|l| other.fd_origin.contains(l)).collect();
        if new_fd_origin != result.fd_origin {
            changed = true;
            result.fd_origin = new_fd_origin;
        }

        // fd_consumed: UNION — escalate double-ownership if consumed on ANY path.
        for &l in &other.fd_consumed {
            if result.fd_consumed.insert(l) {
                changed = true;
            }
        }

        // thread_spawned: OR — once a thread was spawned on any path, it's concurrent.
        if other.thread_spawned && !result.thread_spawned {
            result.thread_spawned = true;
            changed = true;
        }

        (result, changed)
    }

    /// Record that `ptr` aliases the interior of owner `owner`.
    pub fn set_owner_alias(&mut self, ptr: Local, owner: Local) {
        self.owner_alias.entry(ptr).or_default().insert(owner);
    }

    /// Propagate any owner-alias from `src` onto `dst` (used for copy/move/cast/
    /// aggregate-field rvalues). Clears `dst`'s entry if `src` has none.
    pub fn copy_owner_alias(&mut self, dst: Local, src: Local) {
        match self.owner_alias.get(&src).cloned() {
            Some(owners) => {
                self.owner_alias.insert(dst, owners);
            }
            None => {
                self.owner_alias.remove(&dst);
            }
        }
    }

    /// A write to (any projection rooted at) `owner` may reassign the field the
    /// alias referred to, so every alias to `owner` is conservatively broken.
    pub fn invalidate_owner(&mut self, owner: Local) {
        for owners in self.owner_alias.values_mut() {
            owners.remove(&owner);
        }
        self.owner_alias.retain(|_, owners| !owners.is_empty());
    }

    /// The owner locals (if any) whose interior `ptr` currently aliases.
    pub fn owners_of(&self, ptr: Local) -> impl Iterator<Item = Local> + '_ {
        self.owner_alias
            .get(&ptr)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    /// Mark all objects reachable from `local` as Escaped and remove tracking.
    pub fn escape_local(&mut self, local: Local) {
        if let Some(objs) = self.points_to.remove(&local) {
            for id in objs {
                // Do not downgrade a freed/reconstituted state to Escaped.
                // An opaque call that receives a stale (MaybeFreed) pointer does
                // not make the stale-ness disappear — other locals that alias the
                // same object should still see it as freed.
                let current = self.heap.get(&id).copied();
                if !matches!(current, Some(HeapState::Reconstituted) | Some(HeapState::MaybeFreed)) {
                    self.heap.insert(id, HeapState::Escaped);
                }
            }
        }
        self.local_proto.remove(&local);
        self.owner_alias.remove(&local);
    }

    pub fn objects_for(&self, local: Local) -> impl Iterator<Item = ObjectId> + '_ {
        self.points_to
            .get(&local)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    /// Returns `true` if any protocol in scope was explicitly forgotten (`mem::forget`),
    /// including guards that arrived as function parameters (tracked via `untracked_forget_seen`).
    pub fn has_forgotten_protocol(&self) -> bool {
        self.untracked_forget_seen
            || self.typestate.values().any(|s| matches!(s, ProtocolState::Forgotten))
    }

    pub fn has_hazard_protocol(&self) -> bool {
        self.typestate.values().any(|s| s.is_hazard())
    }

    /// Returns `true` if every tracked object reachable from `local` is in the
    /// `RawOwned` state — i.e. the pointer came from a live `into_raw` call and
    /// the backing allocation has not been reconstituted or freed yet.
    /// Returns `false` if no objects are tracked (pointer is untracked / escaped).
    pub fn ptr_is_raw_owned(&self, local: Local) -> bool {
        let objs: Vec<_> = self.objects_for(local).collect();
        !objs.is_empty()
            && objs
                .iter()
                .all(|id| matches!(self.heap.get(id), Some(HeapState::RawOwned)))
    }

    /// Returns `true` if `local` was proven to be strictly less than some tracked
    /// length by an `Assert` terminator over a `Lt`/`Ge` comparison.
    pub fn local_is_bounded(&self, local: Local) -> bool {
        self.bounded.contains(&local)
    }

    /// Returns `true` if `local` was proven to be ≤ some value by an `Assert`
    /// terminator over a `Le`/`Gt` comparison. Also returns `true` when
    /// `local_is_bounded` is true (< implies <=).
    pub fn local_is_bounded_or_eq(&self, local: Local) -> bool {
        self.bounded.contains(&local) || self.bounded_or_eq.contains(&local)
    }

    /// Returns `true` if the collection in `local` was proven to currently have
    /// spare capacity (`len < capacity`) on all reaching paths — e.g. guarded by
    /// `if v.len() < v.capacity() { v.push_unchecked(x) }`. Used to suppress the
    /// capacity-checked-unchecked checkers (`push_unchecked`, …).
    pub fn collection_has_spare(&self, local: Local) -> bool {
        self.has_spare.contains(&local)
    }

    /// Returns `true` if `local` is proven ≠ 0 on all reaching paths — either
    /// by an explicit `!= 0` guard or because its proven lower bound is ≥ 1.
    pub fn local_is_nonzero(&self, local: Local) -> bool {
        self.nonzero.contains(&local)
            || self.const_lower.get(&local).map_or(false, |&lb| lb >= 1)
    }

    /// Returns `true` if `local` (a float) is proven not-NaN on all reaching
    /// paths — e.g. guarded by `if !f.is_nan()` or `if f.is_finite()`.
    pub fn local_is_finite(&self, local: Local) -> bool {
        self.finite.contains(&local)
    }

    /// Returns `true` if `local` (a `u32`) is proven to be a valid Unicode
    /// scalar value on all reaching paths: in range 0x0000..=0xD7FF or
    /// 0xE000..=0x10FFFF (the two disjoint halves of the valid scalar space
    /// that exclude the surrogate range 0xD800..=0xDFFF).
    pub fn local_is_valid_scalar(&self, local: Local) -> bool {
        let upper = self.const_upper.get(&local).copied();
        let lower = self.const_lower.get(&local).copied();
        // Must be within the Unicode range.
        let in_range = upper.map_or(false, |u| u <= 0x10FFFF);
        if !in_range {
            return false;
        }
        // Must not overlap the surrogate range [0xD800, 0xDFFF].
        let below_surrogates = upper.map_or(false, |u| u < 0xD800);  // ≤ 0xD7FF
        let above_surrogates = lower.map_or(false, |l| l > 0xDFFF);  // ≥ 0xE000
        below_surrogates || above_surrogates
    }

    /// Proven constant upper bound for `local` (i.e. `local ≤ bound`), or `None`.
    pub fn local_upper_bound(&self, local: Local) -> Option<u64> {
        self.const_upper.get(&local).copied()
    }

    /// Proven constant lower bound for `local` (i.e. `local ≥ bound`), or `None`.
    pub fn local_lower_bound(&self, local: Local) -> Option<u64> {
        self.const_lower.get(&local).copied()
    }

    /// Returns `true` if the collection in `local` was proven to be exactly full
    /// (`len == capacity`) on all reaching paths — e.g. guarded by
    /// `if v.len() == v.capacity() { v.into_inner_unchecked() }`. Used to
    /// suppress the "must be full" unchecked APIs.
    pub fn collection_is_full(&self, local: Local) -> bool {
        self.is_full.contains(&local)
    }

    /// Resolve a (possibly reborrowed) local to the base collection local it
    /// borrows, following one `ref_base` hop. Returns `local` itself if it is
    /// not a tracked reborrow.
    pub fn deref_base(&self, local: Local) -> Local {
        self.ref_base.get(&local).copied().unwrap_or(local)
    }

    /// Returns `true` if `a` and `b` are proven == on ALL reaching paths — e.g.
    /// from `if a == b` or `assert_eq!(a, b)`. Also looks through one level of
    /// integer cast so that `k as isize` is recognised as equal to the `k` source.
    pub fn locals_are_eq(&self, a: Local, b: Local) -> bool {
        if a == b { return true; }
        let canon = |x: Local, y: Local| if x.index() <= y.index() { (x, y) } else { (y, x) };
        if self.eq_locals.contains(&canon(a, b)) { return true; }
        let a0 = self.cast_origin.get(&a).copied();
        let b0 = self.cast_origin.get(&b).copied();
        match (a0, b0) {
            (Some(sa), _) if sa == b => true,
            (_, Some(sb)) if sb == a => true,
            (Some(sa), Some(sb)) if sa == sb => true,
            (Some(sa), _) => self.eq_locals.contains(&canon(sa, b)),
            (_, Some(sb)) => self.eq_locals.contains(&canon(a, sb)),
            _ => false,
        }
    }

    /// Returns `true` if `a` and `b` are proven ≠ on ALL reaching paths — e.g.
    /// from an explicit `if key1 != key2` guard. Used to suppress
    /// `Slab::get2_unchecked_mut` when the two keys are provably disjoint.
    pub fn locals_are_ne(&self, a: Local, b: Local) -> bool {
        let pair = if a.index() <= b.index() { (a, b) } else { (b, a) };
        self.keys_are_ne.contains(&pair)
    }

    /// Returns the ordered component locals for an array/tuple aggregate, or
    /// `None` if `local` was not recorded as an aggregate with all-local elements.
    /// Used to decompose multi-dimensional ndarray/simd index locals into scalar
    /// components that can each be checked with `local_is_bounded`.
    pub fn array_components_of(&self, local: Local) -> Option<&Vec<Local>> {
        self.array_components.get(&local)
    }

    /// Returns `true` if `local` is a fully bounded index on ALL reaching paths:
    /// either a directly bounded scalar (`local_is_bounded`) or an array/tuple
    /// aggregate whose every component local is bounded. Drives suppression in
    /// the `unsafe_fn_call` backstop for multi-dimensional APIs like ndarray `uget`.
    pub fn index_is_fully_bounded(&self, local: Local) -> bool {
        if let Some(components) = self.array_components.get(&local) {
            !components.is_empty() && components.iter().all(|&c| self.local_is_bounded(c))
        } else {
            self.local_is_bounded(local)
        }
    }

    /// Returns `true` if `local` holds a raw fd integer produced by
    /// `into_raw_fd/socket/handle` on ALL reaching paths — the canonical
    /// transfer pattern; the corresponding `from_raw_fd` is safe.
    pub fn fd_was_transferred(&self, local: Local) -> bool {
        self.fd_origin.contains(&local)
    }

    /// Returns `true` if `local` holds a raw fd integer that was already
    /// consumed by a previous `from_raw_fd/socket/handle` call on ANY reaching
    /// path — a second `from_raw_*` on the same integer is double-ownership.
    pub fn fd_is_consumed(&self, local: Local) -> bool {
        self.fd_consumed.contains(&local)
    }

    /// Classifies whether using the pointer in `local` is a use-after-free.
    /// An object is "freed" once its backing allocation's ownership was handed
    /// off: `Reconstituted` (a `from_raw`/consuming call took it). `MaybeFreed`
    /// means freed on at least one joined control-flow path. `Escaped` is NOT
    /// freed — its provenance is merely unknown, so using it is not provably a
    /// UAF and must not be flagged.
    pub fn freed_kind(&self, local: Local) -> FreedKind {
        let objs: Vec<_> = self.objects_for(local).collect();
        if objs.is_empty() {
            return FreedKind::NotFreed;
        }
        let mut any_freed = false;
        let mut all_reconstituted = true;
        for id in &objs {
            match self.heap.get(id) {
                Some(HeapState::Reconstituted) => any_freed = true,
                Some(HeapState::MaybeFreed) => {
                    any_freed = true;
                    all_reconstituted = false;
                }
                _ => all_reconstituted = false,
            }
        }
        match (any_freed, all_reconstituted) {
            (true, true) => FreedKind::Definite,
            (true, false) => FreedKind::Potential,
            _ => FreedKind::NotFreed,
        }
    }
}

/// Result of [`BlockState::freed_kind`]: whether dereferencing a pointer is a
/// use-after-free.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreedKind {
    /// No tracked object is freed (or the pointer is untracked / escaped).
    NotFreed,
    /// Every tracked object was reconstituted on all paths — a definite UAF.
    Definite,
    /// Freed on some path / some object — a potential UAF.
    Potential,
}
