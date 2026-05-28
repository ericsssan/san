use std::collections::{BTreeSet, HashMap};

use rustc_middle::mir::Local;

use crate::analysis::object::{HeapMap, HeapState, ObjectId};
use crate::analysis::typestate::{ProtocolId, ProtocolState, TypestateMap};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BlockState {
    pub heap: HeapMap,
    /// Each Local may point to a set of abstract objects (join = union).
    pub points_to: HashMap<Local, BTreeSet<ObjectId>>,
    /// Local holding a protocol instance (guard, lock guard, etc.).
    pub local_proto: HashMap<Local, ProtocolId>,
    pub typestate: TypestateMap,
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

        for (local, proto_id) in &other.local_proto {
            result.local_proto.entry(*local).or_insert_with(|| {
                changed = true;
                *proto_id
            });
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

    pub fn has_forgotten_protocol(&self) -> bool {
        self.typestate
            .values()
            .any(|s| matches!(s, ProtocolState::Forgotten))
    }

    pub fn has_hazard_protocol(&self) -> bool {
        self.typestate.values().any(|s| s.is_hazard())
    }
}
