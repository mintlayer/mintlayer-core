use common::primitives::Uint256;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct Compact(pub(crate) u32);

impl From<Uint256> for Compact {
    fn from(_: Uint256) -> Self {
        todo!()
    }
}

impl Into<Uint256> for Compact {
    fn into(self) -> Uint256 {
        todo!()
    }
}
