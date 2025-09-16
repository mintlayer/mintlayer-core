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

use common::chain::{
    htlc::HtlcSecret, partially_signed_transaction::PartiallySignedTransactionConsistencyCheck,
    signature::inputsig::InputWitness, Destination, Transaction, TxOutput,
};

pub use common::chain::partially_signed_transaction::{
    make_sighash_input_commitments, OrderAdditionalInfo, PartiallySignedTransaction,
    PartiallySignedTransactionError, PoolAdditionalInfo, SighashInputCommitmentCreationError,
    TokenAdditionalInfo, TxAdditionalInfo,
};

pub trait PartiallySignedTransactionWalletExt {
    fn new_for_wallet(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
    ) -> Result<PartiallySignedTransaction, PartiallySignedTransactionError>;
}

impl PartiallySignedTransactionWalletExt for PartiallySignedTransaction {
    fn new_for_wallet(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
    ) -> Result<Self, PartiallySignedTransactionError> {
        let consistency_checks = if cfg!(debug_assertions) {
            PartiallySignedTransactionConsistencyCheck::AdditionalInfoWithTokenInfos
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
