use crate::chain::block::block_v1::ConsensusData;
use crate::primitives::Compact;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoWData {
    pub bits: Compact,
    pub nonce: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Data {
    PoW(PoWData),
}

#[derive(Debug)]
pub enum DataError {
    ConversionError(String), // can be renamed to something else
}

impl From<Data> for ConsensusData {
    fn from(d: Data) -> Self {
        d.encode()
    }
}

impl TryFrom<ConsensusData> for Data {
    type Error = DataError;

    fn try_from(value: ConsensusData) -> Result<Self, Self::Error> {
        Decode::decode(&mut &value[..]).map_err(|e| {
            let str = format!("{:?}", e);
            DataError::ConversionError(str)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::block::data::{Data, PoWData};
    use crate::chain::block::ConsensusData;
    use crate::primitives::Compact;
    use crate::Uint256;

    #[test]
    fn conversion_check() {
        let pow = {
            let data = PoWData {
                bits: Compact::from(Uint256::from_u64(0).expect("should be ok")),
                nonce: 0,
            };
            Data::PoW(data)
        };

        let pow_vec = ConsensusData::from(pow.clone());
        assert_eq!(
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pow_vec
        );

        match Data::try_from(pow_vec) {
            Ok(decoded) => {
                assert_eq!(pow, decoded);
            }
            Err(e) => {
                panic!("this shouldn't fail: {:?}", e);
            }
        }
    }
}
