// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common::{
    chain::{
        block::signed_block_header::{BlockHeaderSignature, SignedBlockHeader},
        Block, Destination,
    },
    primitives::{Id, Idable},
};
use serialization::Encode;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockSignatureError {
    #[error("Block signature not found in block {0}")]
    BlockSignatureNotFound(Id<Block>),
    #[error("Wrong destination for block signature in block {0}")]
    WrongDestination(Id<Block>),
    #[error("Bad block signature in block {0}")]
    BadSignature(Id<Block>),
}

/// Checks the signature of the block (in its header) against the provided destination.
pub fn check_block_signature(
    header: &SignedBlockHeader,
    staker: &Destination,
) -> Result<(), BlockSignatureError> {
    let public_key = match staker {
        Destination::AnyoneCanSpend
        | Destination::PublicKeyHash(_)
        | Destination::ScriptHash(_)
        | Destination::ClassicMultisig(_) => {
            return Err(BlockSignatureError::WrongDestination(header.get_id()))
        }
        Destination::PublicKey(pk) => pk,
    };

    let signature_in_header = header.signature_data();

    let sig_data = match signature_in_header {
        BlockHeaderSignature::None => {
            return Err(BlockSignatureError::BlockSignatureNotFound(header.get_id()))
        }
        BlockHeaderSignature::HeaderSignature(sig_data) => sig_data,
    };

    if !public_key.verify_message(sig_data.signature(), &header.header().encode()) {
        return Err(BlockSignatureError::BadSignature(header.get_id()));
    }

    Ok(())
}

// TODO: tests
