// Copyright (c) 2022 RBB S.r.l
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
    chain::{block::GenBlock, OutPointSourceId, Transaction},
    primitives::Id,
};
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum Error {
    #[error("Attempted to overwrite an existing utxo")]
    OverwritingUtxo,
    #[error(
        "The utxo was marked FRESH in the child cache, but the utxo exists in the parent cache. This can be considered a fatal error."
    )]
    FreshUtxoAlreadyExists,
    #[error("Attempted to spend a UTXO that's already spent")]
    UtxoAlreadySpent(OutPointSourceId),
    #[error("Attempted to spend a non-existing UTXO")]
    NoUtxoFound,
    #[error("Attempted to get the block height of a UTXO source that is based on the mempool")]
    NoBlockchainHeightFound,
    #[error("Block reward undo info is missing while unspending the utxo for block `{0}`")]
    MissingBlockRewardUndo(Id<GenBlock>),
    #[error("Block reward type is invalid `{0}`")]
    InvalidBlockRewardOutputType(Id<GenBlock>),
    #[error("Undo for transaction `{0}` doesn't match inputs")]
    TxInputAndUndoMismatch(Id<Transaction>),

    // TODO This is a temporary solution. It does not provide much information, the exact utxo
    //      view error is lost. The concrete error type depends on the UtxoView used. The error
    //      enum here should be parametrized by the error type rather than hide it, so the error
    //      type information is available at compilation time and the exact error emitted from
    //      UtxoView is available to the caller at run time. That, however, leads to many call
    //      sites having to be updated so it's left for future improvements.
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("UTXO view query failed `for some reason (TM)`")]
    ViewRead,
    #[error("UTXO storage write failed `for some reason (TM)`")]
    StorageWrite,
}
