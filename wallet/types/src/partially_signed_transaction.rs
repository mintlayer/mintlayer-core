// Copyright (c) 2021-2025 RBB S.r.l
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

use std::collections::BTreeMap;

use common::chain::{
    htlc::HtlcSecret, partially_signed_transaction::PartiallySignedTransactionConsistencyCheck,
    signature::inputsig::InputWitness, tokens::TokenId, Destination, OrderId, PoolId, Transaction,
    TxOutput,
};

pub use common::chain::partially_signed_transaction::{
    make_sighash_input_commitments, OrderAdditionalInfo, PartiallySignedTransaction,
    PartiallySignedTransactionError, PoolAdditionalInfo, SighashInputCommitmentCreationError,
    TxAdditionalInfo as PtxAdditionalInfo,
};

pub trait PartiallySignedTransactionWalletExt {
    fn new_for_wallet(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: PtxAdditionalInfo,
    ) -> Result<PartiallySignedTransaction, PartiallySignedTransactionError>;
}

impl PartiallySignedTransactionWalletExt for PartiallySignedTransaction {
    fn new_for_wallet(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: PtxAdditionalInfo,
    ) -> Result<Self, PartiallySignedTransactionError> {
        let consistency_checks = if cfg!(debug_assertions) {
            PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo
        } else {
            PartiallySignedTransactionConsistencyCheck::Basic
        };

        Self::new(
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
            consistency_checks,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAdditionalInfo {
    pub num_decimals: u8,
    pub ticker: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokensAdditionalInfo {
    infos: BTreeMap<TokenId, TokenAdditionalInfo>,
}

impl TokensAdditionalInfo {
    pub fn new() -> Self {
        Self {
            infos: BTreeMap::new(),
        }
    }

    pub fn with_info(mut self, token_id: TokenId, info: TokenAdditionalInfo) -> Self {
        self.infos.insert(token_id, info);
        self
    }

    pub fn add_info(&mut self, token_id: TokenId, info: TokenAdditionalInfo) {
        self.infos.insert(token_id, info);
    }

    pub fn join(mut self, other: Self) -> Self {
        self.infos.extend(other.infos);
        self
    }

    pub fn get_info(&self, token_id: &TokenId) -> Option<&TokenAdditionalInfo> {
        self.infos.get(token_id)
    }

    pub fn info_iter(&self) -> impl Iterator<Item = (&'_ TokenId, &'_ TokenAdditionalInfo)> {
        self.infos.iter()
    }
}

#[derive(Clone, Debug)]
pub struct TxAdditionalInfo {
    pub ptx_additional_info: PtxAdditionalInfo,
    pub tokens_additional_info: TokensAdditionalInfo,
}

impl TxAdditionalInfo {
    pub fn new() -> Self {
        Self {
            ptx_additional_info: PtxAdditionalInfo::new(),
            tokens_additional_info: TokensAdditionalInfo::new(),
        }
    }

    pub fn with_token_info(mut self, token_id: TokenId, info: TokenAdditionalInfo) -> Self {
        self.tokens_additional_info = self.tokens_additional_info.with_info(token_id, info);
        self
    }

    pub fn with_pool_info(mut self, pool_id: PoolId, info: PoolAdditionalInfo) -> Self {
        self.ptx_additional_info = self.ptx_additional_info.with_pool_info(pool_id, info);
        self
    }

    pub fn with_order_info(mut self, order_id: OrderId, info: OrderAdditionalInfo) -> Self {
        self.ptx_additional_info = self.ptx_additional_info.with_order_info(order_id, info);
        self
    }

    pub fn get_token_info(&self, token_id: &TokenId) -> Option<&TokenAdditionalInfo> {
        self.tokens_additional_info.get_info(token_id)
    }
}
