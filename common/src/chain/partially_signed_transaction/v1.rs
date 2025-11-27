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

use serialization::{Decode, Encode};
use utils::ensure;

use crate::chain::{
    htlc::HtlcSecret,
    partially_signed_transaction::{
        PartiallySignedTransactionConsistencyCheck, PartiallySignedTransactionError,
        TxAdditionalInfo,
    },
    signature::inputsig::InputWitness,
    AccountCommand, Destination, OrderAccountCommand, OrderId, SignedTransaction, Transaction,
    TxInput, TxOutput,
};

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode, serde::Serialize)]
pub struct PartiallySignedTransactionV1 {
    tx: Transaction,
    witnesses: Vec<Option<InputWitness>>,

    input_utxos: Vec<Option<TxOutput>>,
    destinations: Vec<Option<Destination>>,

    htlc_secrets: Vec<Option<HtlcSecret>>,
    additional_info: TxAdditionalInfo,
}

impl PartiallySignedTransactionV1 {
    // Note: passing `None` for `htlc_secrets` is equivalent to passing a `Vec` of `None`s.
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
        consistency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<Self, PartiallySignedTransactionError> {
        let this = Self::new_unchecked(
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
        );

        this.ensure_consistency(consistency_check)?;
        Ok(this)
    }

    fn new_unchecked(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
    ) -> Self {
        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);

        Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
        }
    }

    pub fn ensure_consistency(
        &self,
        consistency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<(), PartiallySignedTransactionError> {
        ensure!(
            self.tx.inputs().len() == self.witnesses.len(),
            PartiallySignedTransactionError::InvalidWitnessCount
        );

        ensure!(
            self.tx.inputs().len() == self.input_utxos.len(),
            PartiallySignedTransactionError::InvalidInputUtxosCount,
        );

        ensure!(
            self.tx.inputs().len() == self.destinations.len(),
            PartiallySignedTransactionError::InvalidDestinationsCount
        );

        ensure!(
            self.tx.inputs().len() == self.htlc_secrets.len(),
            PartiallySignedTransactionError::InvalidHtlcSecretsCount
        );

        match consistency_check {
            PartiallySignedTransactionConsistencyCheck::Basic => {}
            PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo => {
                self.ensure_additional_info_completeness()?;
            }
        }

        Ok(())
    }

    fn ensure_additional_info_completeness(&self) -> Result<(), PartiallySignedTransactionError> {
        // TODO: try to re-use the input commitments machinery here instead of doing custom checks.

        let ensure_order_info_present =
            |order_id: &OrderId| -> Result<_, PartiallySignedTransactionError> {
                ensure!(
                    self.additional_info.get_order_info(order_id).is_some(),
                    PartiallySignedTransactionError::OrderAdditionalInfoMissing(*order_id)
                );
                Ok(())
            };

        let ensure_no_utxo = |input_index,
                              input_utxo_opt: &Option<TxOutput>|
         -> Result<_, PartiallySignedTransactionError> {
            ensure!(
                input_utxo_opt.is_none(),
                PartiallySignedTransactionError::UtxoPresentForNonUtxoInput { input_index }
            );
            Ok(())
        };

        let check_utxo = |output: &TxOutput| -> Result<(), PartiallySignedTransactionError> {
            match output {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    ensure!(
                        self.additional_info.get_pool_info(pool_id).is_some(),
                        PartiallySignedTransactionError::PoolAdditionalInfoMissing(*pool_id)
                    );
                }
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => {}
            }
            Ok(())
        };

        for (input_index, (input, input_utxo)) in
            self.tx.inputs().iter().zip(self.input_utxos.iter()).enumerate()
        {
            match input {
                TxInput::Utxo(_) => {
                    let input_utxo = input_utxo.as_ref().ok_or(
                        PartiallySignedTransactionError::MissingUtxoForUtxoInput { input_index },
                    )?;
                    check_utxo(input_utxo)?;
                }
                TxInput::Account(_) => ensure_no_utxo(input_index, input_utxo)?,
                TxInput::AccountCommand(_, command) => {
                    ensure_no_utxo(input_index, input_utxo)?;

                    match command {
                        AccountCommand::ConcludeOrder(id) => ensure_order_info_present(id)?,
                        AccountCommand::FillOrder(id, _, _) => ensure_order_info_present(id)?,

                        AccountCommand::MintTokens(_, _)
                        | AccountCommand::UnmintTokens(_)
                        | AccountCommand::LockTokenSupply(_)
                        | AccountCommand::FreezeToken(_, _)
                        | AccountCommand::UnfreezeToken(_)
                        | AccountCommand::ChangeTokenAuthority(_, _)
                        | AccountCommand::ChangeTokenMetadataUri(_, _) => {}
                    }
                }
                TxInput::OrderAccountCommand(command) => {
                    match command {
                        OrderAccountCommand::FillOrder(id, _)
                        | OrderAccountCommand::ConcludeOrder(id) => ensure_order_info_present(id)?,

                        OrderAccountCommand::FreezeOrder(_) => {}
                    };
                }
            }
        }

        Ok(())
    }

    pub fn with_witnesses(
        mut self,
        witnesses: Vec<Option<InputWitness>>,
    ) -> Result<Self, PartiallySignedTransactionError> {
        ensure!(
            witnesses.len() == self.tx.inputs().len(),
            PartiallySignedTransactionError::InvalidWitnessCount
        );
        self.witnesses = witnesses;
        Ok(self)
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn take_tx(self) -> Transaction {
        self.tx
    }

    pub fn input_utxos(&self) -> &[Option<TxOutput>] {
        self.input_utxos.as_ref()
    }

    pub fn input_destinations(&self) -> &[Option<Destination>] {
        self.destinations.as_ref()
    }

    pub fn witnesses(&self) -> &[Option<InputWitness>] {
        self.witnesses.as_ref()
    }

    pub fn htlc_secrets(&self) -> &[Option<HtlcSecret>] {
        self.htlc_secrets.as_ref()
    }

    // Note: this function only checks that all inputs that require a signature have one.
    // I.e. it doesn't check whether a multisig input has all required signatures.
    // TODO: rename it at least or make private.
    pub fn all_signatures_available(&self) -> bool {
        self.witnesses
            .iter()
            .enumerate()
            .zip(&self.destinations)
            .all(|((_, witness), dest)| {
                let dest_needs_signature = match dest {
                    Some(dest) => match dest {
                        Destination::AnyoneCanSpend => false,
                        Destination::PublicKeyHash(_)
                        | Destination::PublicKey(_)
                        | Destination::ScriptHash(_)
                        | Destination::ClassicMultisig(_) => true,
                    },
                    None => false,
                };

                match (witness, dest_needs_signature) {
                    (Some(InputWitness::NoSignature(_)), false) => true,
                    (Some(InputWitness::NoSignature(_)), true) => false,
                    // TODO: consider returning a Result and produce an error in this case.
                    (Some(InputWitness::Standard(_)), false) => false,
                    (Some(InputWitness::Standard(_)), true) => true,
                    (None, _) => false,
                }
            })
    }

    pub fn into_signed_tx(self) -> Result<SignedTransaction, PartiallySignedTransactionError> {
        if self.all_signatures_available() {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)
                .map_err(PartiallySignedTransactionError::TxCreationError)?)
        } else {
            Err(
                PartiallySignedTransactionError::FailedToConvertPartiallySignedTx(Box::new(
                    self.into(),
                )),
            )
        }
    }

    pub fn additional_info(&self) -> &TxAdditionalInfo {
        &self.additional_info
    }
}
