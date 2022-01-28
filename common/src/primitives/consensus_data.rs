#![allow(clippy::from_over_into)]

use crate::primitives::Compact;
use parity_scale_codec::{Decode, Encode};
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ConsensusData {
    None,
    PoW(PoWData),
}

impl Into<u8> for ConsensusData {
    fn into(self) -> u8 {
        match self {
            ConsensusData::None => 0,
            ConsensusData::PoW(_) => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoWData {
    bits: Compact,
    nonce: u128,
}

#[cfg(test)]
mod tests {
    use crate::primitives::consensus_data::{ConsensusData, PoWData};
    use crate::primitives::Compact;
    use crate::Uint256;

    #[test]
    fn index_check() {
        let pow = ConsensusData::PoW(PoWData {
            bits: Compact::from(Uint256::from_u64(0).expect("should be ok")),
            nonce: 0,
        });

        let pow_num: u8 = pow.into();
        assert_eq!(1u8, pow_num);
    }
}
