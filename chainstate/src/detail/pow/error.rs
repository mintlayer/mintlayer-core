use common::{
    chain::block::Block,
    primitives::{BlockHeight, Compact, Id},
};
use thiserror::Error;

use crate::detail::PropertyQueryError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoWError {
    #[error("Blockchain storage error: {0}")]
    StorageError(blockchain_storage::Error),
    #[error("Invalid Proof of Work for block {0}")]
    InvalidPoW(Id<Block>),
    #[error("Error while loading previous block {0} of block {1} with error {2}")]
    PrevBlockLoadError(Id<Block>, Id<Block>, PropertyQueryError),
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Error while loading ancestor of block {0} at height {1} with error {2}")]
    AncestorAtHeightNotFound(Id<Block>, BlockHeight, PropertyQueryError),
    #[error("No PoW data for block for block")]
    NoPowDataInPreviousBlock,
    #[error("Decoding bits of block failed: `{0:?}`")]
    DecodingBitsFailed(Compact),
    #[error("Previous bits conversion failed: `{0:?}`")]
    PreviousBitsDecodingFailed(Compact),
}
