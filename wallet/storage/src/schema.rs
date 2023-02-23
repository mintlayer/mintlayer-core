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

//! Wallet database schema

use wallet_types::WalletTx;

use common::{
    chain::{OutPoint, Transaction},
    primitives::Id,
};
use utxo::Utxo;

storage::decl_schema! {
    /// Database schema for wallet storage
    pub Schema {
        /// Storage for individual values.
        pub DBValue: Map<Vec<u8>, Vec<u8>>,
        /// Store for Utxo Entries
        pub DBUtxo: Map<OutPoint, Utxo>,
        /// Store for Transaction entries
        pub DBTxs: Map<Id<Transaction>, WalletTx>,
    }
}
