use util::Uint256;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct Compact(pub(crate) Vec<u8>);

impl Compact {
    pub fn convert_to_uint256(&self) -> Uint256 {
        todo!()
    }

    pub fn from_uint256(u256: Uint256) -> Self {
        todo!()
    }
}
