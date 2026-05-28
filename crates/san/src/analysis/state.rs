use std::collections::{BTreeSet, HashMap};

use rustc_middle::mir::Local;

use crate::analysis::object::{HeapMap, HeapState, ObjectId};
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
}
