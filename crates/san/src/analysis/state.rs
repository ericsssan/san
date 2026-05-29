use std::collections::{BTreeSet, HashMap, HashSet};

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
    /// Locals proven to be < some length (via Assert terminator). Join is INTERSECTION.
    pub bounded: HashSet<Local>,
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

        (result, changed)
    }

    /// Mark all objects reachable from `local` as Escaped and remove tracking.
    pub fn escape_local(&mut self, local: Local) {
        if let Some(objs) = self.points_to.remove(&local) {
            for id in objs {
                self.heap.insert(id, HeapState::Escaped);
            }
        }
        self.local_proto.remove(&local);
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
