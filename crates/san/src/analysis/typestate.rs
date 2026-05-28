use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProtocolId(pub u32);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProtocolState {
    Active,
    Consumed,
    Forgotten,
    MaybeActive,
}

impl ProtocolState {
    pub fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        ProtocolState::MaybeActive
    }

    pub fn is_hazard(&self) -> bool {
        matches!(self, ProtocolState::Consumed | ProtocolState::MaybeActive)
    }
}

pub type TypestateMap = HashMap<ProtocolId, ProtocolState>;
