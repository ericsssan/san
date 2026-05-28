use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectId(pub u32);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HeapState {
    RawOwned,
    Reconstituted,
    MaybeFreed,
    Escaped,
}

impl HeapState {
    pub fn join(&self, other: &Self) -> Self {
        use HeapState::*;
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Escaped, _) | (_, Escaped) => Escaped,
            (MaybeFreed, _) | (_, MaybeFreed) => MaybeFreed,
            _ => MaybeFreed,
        }
    }

    pub fn is_hazard(&self) -> bool {
        matches!(self, HeapState::MaybeFreed)
    }
}

pub type HeapMap = HashMap<ObjectId, HeapState>;
