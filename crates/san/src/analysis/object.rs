use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectId(pub u32);

/// Initialization state for a `MaybeUninit` local.
///
/// `Initialized` means the local is provably initialized (e.g., via `MaybeUninit::new`,
/// `MaybeUninit::zeroed`, or `MaybeUninit::write`). `Unknown` means we cannot prove it.
/// The join of `Initialized` and any other value is `Unknown` (conservative).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InitState {
    /// The local is known to be fully initialized.
    Initialized,
    /// The local may or may not be initialized (top / unknown).
    Unknown,
}

impl InitState {
    pub fn join(&self, other: &Self) -> Self {
        if self == other { self.clone() } else { InitState::Unknown }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
