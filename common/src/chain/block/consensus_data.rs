use crate::chain::TxInput;
use crate::chain::{signature::Transactable, TxOutput};
use crate::primitives::Compact;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Encode, Decode)]
pub enum ConsensusData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    PoW(PoWData),
}

pub struct BlockRewardTransactable<'a> {
    inputs: Option<&'a [TxInput]>,
    outputs: Option<&'a [TxOutput]>,
}

impl<'a> Transactable for BlockRewardTransactable<'a> {
    fn inputs(&self) -> Option<&[TxInput]> {
        self.inputs
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        self.outputs
    }

    fn version_byte(&self) -> Option<u8> {
        None
    }

    fn lock_time(&self) -> Option<u32> {
        None
    }

    fn flags(&self) -> Option<u32> {
        None
    }
}

impl ConsensusData {
    pub fn derive_transactable<'a>(&'a self) -> BlockRewardTransactable {
        match self {
            ConsensusData::None => BlockRewardTransactable {
                inputs: None,
                outputs: None,
            },
            ConsensusData::PoW(ref pow_data) => BlockRewardTransactable {
                inputs: None,
                outputs: Some(pow_data.outputs()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Encode, Decode)]
pub struct PoWData {
    bits: Compact,
    nonce: u128,
    reward_outputs: Vec<TxOutput>,
}

impl PoWData {
    pub fn new(bits: Compact, nonce: u128, reward_outputs: Vec<TxOutput>) -> Self {
        PoWData {
            bits,
            nonce,
            reward_outputs,
        }
    }
    pub fn bits(&self) -> Compact {
        self.bits
    }

    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.reward_outputs
    }

    pub fn update_nonce(&mut self, nonce: u128) {
        self.nonce = nonce;
    }
}
