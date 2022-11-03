use super::derivation_path::ChildNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainCode([u8; 32]);

impl From<[u8; 32]> for ChainCode {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

impl From<ChainCode> for [u8; 32] {
    fn from(cc: ChainCode) -> Self {
        cc.0
    }
}

impl From<ChildNumber> for ChainCode {
    fn from(num: ChildNumber) -> Self {
        let mut chaincode = ChainCode([0u8; 32]);
        chaincode.0[0..4].copy_from_slice(&num.to_encoded_index().to_be_bytes());
        chaincode
    }
}
