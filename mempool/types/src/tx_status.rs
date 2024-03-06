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

/// Result of adding transaction to the mempool
#[derive(
    Debug,
    PartialEq,
    PartialOrd,
    Eq,
    Ord,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
)]
#[must_use = "Please check whether the tx was accepted to main mempool or orphan pool"]
pub enum TxStatus {
    /// Transaction is in mempool
    InMempool,

    /// Transaction has already been in the mempool, duplicate insertion
    InMempoolDuplicate,

    /// Transaction is in orphan pool
    InOrphanPool,

    /// Transaction has already been in the orphan pool, duplicate insertion
    InOrphanPoolDuplicate,
}

impl TxStatus {
    /// Transaction is in mempool, whether freshly inserted or not
    pub fn in_mempool(&self) -> bool {
        match self {
            TxStatus::InMempool => true,
            TxStatus::InMempoolDuplicate => true,
            TxStatus::InOrphanPool => false,
            TxStatus::InOrphanPoolDuplicate => false,
        }
    }

    /// Transaction is in orphan pool, whether freshly inserted or not
    pub fn in_orphan_pool(&self) -> bool {
        match self {
            TxStatus::InMempool => false,
            TxStatus::InMempoolDuplicate => false,
            TxStatus::InOrphanPool => true,
            TxStatus::InOrphanPoolDuplicate => true,
        }
    }

    /// The transaction was already in mempool or orphan pool
    pub fn is_duplicate(&self) -> bool {
        match self {
            TxStatus::InMempool => false,
            TxStatus::InMempoolDuplicate => true,
            TxStatus::InOrphanPool => false,
            TxStatus::InOrphanPoolDuplicate => true,
        }
    }
}
