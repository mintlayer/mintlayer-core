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

use common::chain::OutPointSourceId;
use crypto::key::hdkd::u31::U31;
use wallet_types::WalletTx;

/// Callbacks that are called when the database is updated and the UI should be re-rendered.
/// For example, when a new wallet is imported and the wallet scan is in progress,
/// the wallet balance and address/transaction lists should be updated after these callbacks.
pub trait WalletEvents {
    /// New block is scanned
    fn new_block(&self);

    /// The transaction is updated in the DB
    fn set_transaction(&self, id: U31, tx: &WalletTx);

    /// The transaction is removed from the DB
    fn del_transaction(&self, id: U31, source_id: OutPointSourceId);
}

pub struct WalletEventsNoOp;

impl WalletEvents for WalletEventsNoOp {
    fn new_block(&self) {}
    fn set_transaction(&self, _id: U31, _tx: &WalletTx) {}
    fn del_transaction(&self, _id: U31, _source: OutPointSourceId) {}
}
