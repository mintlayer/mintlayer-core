// Copyright (c) 2024 RBB S.r.l
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

use std::sync::Arc;

use common::chain::{
    signature::{
        inputsig::{
            arbitrary_message::ArbitraryMessageSignature,
            classical_multisig::authorize_classical_multisig::{
                sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                ClassicalMultisigCompletionStatus,
            },
            standard_signature::StandardInputSignature,
            InputWitness,
        },
        sighash::{sighashtype::SigHashType, signature_hash},
        DestinationSigError,
    },
    ChainConfig, Destination, Transaction, TxOutput,
};
use crypto::key::{
    extended::{ExtendedPrivateKey, ExtendedPublicKey},
    hdkd::{derivable::Derivable, u31::U31},
    PrivateKey,
};
use itertools::Itertools;
use randomness::make_true_rng;
use serialization::Encode;
use wallet_storage::WalletStorageReadUnlocked;
use wallet_types::signature_status::SignatureStatus;

use crate::{
    account::PartiallySignedTransaction,
    key_chain::{make_account_path, AccountKeyChains, FoundPubKey, MasterKeyChain},
};

use super::{Signer, SignerError, SignerProvider, SignerResult};

pub struct SoftwareSigner {
    chain_config: Arc<ChainConfig>,
    account_index: U31,
}

impl SoftwareSigner {
    pub fn new(chain_config: Arc<ChainConfig>, account_index: U31) -> Self {
        Self {
            chain_config,
            account_index,
        }
    }

    fn derive_account_private_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<ExtendedPrivateKey> {
        let account_path = make_account_path(&self.chain_config, self.account_index);

        let root_key = MasterKeyChain::load_root_key(db_tx)?.derive_absolute_path(&account_path)?;
        Ok(root_key)
    }

    fn get_private_key_for_destination(
        &self,
        destination: &Destination,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<Option<PrivateKey>> {
        let xpriv = self.derive_account_private_key(db_tx)?;
        match key_chain.find_public_key(destination) {
            Some(FoundPubKey::Hierarchy(xpub)) => {
                get_private_key(&xpriv, &xpub).map(|pk| Some(pk.private_key()))
            }
            Some(FoundPubKey::Standalone(acc_public_key)) => {
                let standalone_pk = db_tx.get_account_standalone_private_key(&acc_public_key)?;
                Ok(standalone_pk)
            }
            None => Ok(None),
        }
    }

    fn sign_input(
        &self,
        tx: &Transaction,
        destination: &Destination,
        input_index: usize,
        input_utxos: &[Option<&TxOutput>],
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)> {
        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKey(_) | Destination::PublicKeyHash(_) => {
                let sig = self
                    .get_private_key_for_destination(destination, key_chain, db_tx)?
                    .map(|private_key| {
                        let sighash_type =
                            SigHashType::try_from(SigHashType::ALL).expect("Should not fail");

                        StandardInputSignature::produce_uniparty_signature_for_input(
                            &private_key,
                            sighash_type,
                            destination.clone(),
                            tx,
                            input_utxos,
                            input_index,
                            make_true_rng(),
                        )
                        .map(InputWitness::Standard)
                        .map_err(SignerError::SigningError)
                    })
                    .transpose()?;

                if sig.is_some() {
                    Ok((sig, SignatureStatus::FullySigned))
                } else {
                    Ok((sig, SignatureStatus::NotSigned))
                }
            }
            Destination::ClassicMultisig(_) => {
                if let Some(challenge) = key_chain.find_multisig_challenge(destination) {
                    let current_signatures =
                        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

                    let (sig, _, status) = self.sign_multisig_input(
                        tx,
                        input_index,
                        input_utxos,
                        current_signatures,
                        key_chain,
                        db_tx,
                    )?;
                    return Ok((sig, status));
                }

                Ok((None, SignatureStatus::NotSigned))
            }
            Destination::ScriptHash(_) => Ok((None, SignatureStatus::NotSigned)),
        }
    }

    fn sign_multisig_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        input_utxos: &[Option<&TxOutput>],
        mut current_signatures: AuthorizedClassicalMultisigSpend,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus, SignatureStatus)> {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).expect("Should not fail");

        let challenge = current_signatures.challenge().clone();
        let sighash = signature_hash(sighash_type, tx, input_utxos, input_index)?;
        let required_signatures = challenge.min_required_signatures();

        let previous_status = SignatureStatus::PartialMultisig {
            required_signatures,
            num_signatures: current_signatures.signatures().len() as u8,
        };

        let mut final_status = previous_status;

        for (key_index, public_key) in challenge.public_keys().iter().enumerate() {
            if current_signatures.signatures().contains_key(&(key_index as u8)) {
                continue;
            }

            if let Some(private_key) = self.get_private_key_for_destination(
                &Destination::PublicKey(public_key.clone()),
                key_chain,
                db_tx,
            )? {
                let res = sign_classical_multisig_spending(
                    &self.chain_config,
                    key_index as u8,
                    &private_key,
                    &challenge,
                    &sighash,
                    current_signatures,
                    &mut make_true_rng(),
                )
                .map_err(DestinationSigError::ClassicalMultisigSigningFailed)?;

                match res {
                    ClassicalMultisigCompletionStatus::Complete(signatures) => {
                        current_signatures = signatures;
                        final_status = SignatureStatus::FullySigned;
                        break;
                    }
                    ClassicalMultisigCompletionStatus::Incomplete(signatures) => {
                        current_signatures = signatures;
                        final_status = SignatureStatus::PartialMultisig {
                            required_signatures,
                            num_signatures: current_signatures.signatures().len() as u8,
                        };
                    }
                };
            }
        }

        Ok((
            Some(InputWitness::Standard(StandardInputSignature::new(
                sighash_type,
                current_signatures.encode(),
            ))),
            previous_status,
            final_status,
        ))
    }
}

impl Signer for SoftwareSigner {
    fn sign_tx(
        &mut self,
        ptx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        let inputs_utxo_refs: Vec<_> = ptx.input_utxos().iter().map(|u| u.as_ref()).collect();

        let (witnesses, prev_statuses, new_statuses) = ptx
            .witnesses()
            .iter()
            .enumerate()
            .zip(ptx.destinations())
            .map(|((i, witness), destination)| match witness {
                Some(w) => match w {
                    InputWitness::NoSignature(_) => Ok((
                        Some(w.clone()),
                        SignatureStatus::FullySigned,
                        SignatureStatus::FullySigned,
                    )),
                    InputWitness::Standard(sig) => match destination {
                        Some(destination) => {
                            let sighash =
                                signature_hash(sig.sighash_type(), ptx.tx(), &inputs_utxo_refs, i)?;

                            if sig
                                .verify_signature(&self.chain_config, destination, &sighash)
                                .is_ok()
                            {
                                Ok((
                                    Some(w.clone()),
                                    SignatureStatus::FullySigned,
                                    SignatureStatus::FullySigned,
                                ))
                            } else if let Destination::ClassicMultisig(_) = destination {
                                let sig_components = AuthorizedClassicalMultisigSpend::from_data(
                                    sig.raw_signature(),
                                )?;

                                self.sign_multisig_input(
                                    ptx.tx(),
                                    i,
                                    &inputs_utxo_refs,
                                    sig_components,
                                    key_chain,
                                    db_tx,
                                )
                            } else {
                                Ok((
                                    None,
                                    SignatureStatus::InvalidSignature,
                                    SignatureStatus::NotSigned,
                                ))
                            }
                        }
                        None => Ok((
                            Some(w.clone()),
                            SignatureStatus::UnknownSignature,
                            SignatureStatus::UnknownSignature,
                        )),
                    },
                },
                None => match destination {
                    Some(destination) => {
                        let (sig, status) = self.sign_input(
                            ptx.tx(),
                            destination,
                            i,
                            &inputs_utxo_refs,
                            key_chain,
                            db_tx,
                        )?;
                        Ok((sig, SignatureStatus::NotSigned, status))
                    }
                    None => Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned)),
                },
            })
            .collect::<Result<Vec<_>, SignerError>>()?
            .into_iter()
            .multiunzip();

        Ok((ptx.new_witnesses(witnesses), prev_statuses, new_statuses))
    }

    fn sign_challenge(
        &mut self,
        message: Vec<u8>,
        destination: Destination,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<ArbitraryMessageSignature> {
        let private_key = self
            .get_private_key_for_destination(&destination, key_chain, db_tx)?
            .ok_or(SignerError::DestinationNotFromThisWallet)?;

        let sig = ArbitraryMessageSignature::produce_uniparty_signature(
            &private_key,
            &destination,
            &message,
            make_true_rng(),
        )?;

        Ok(sig)
    }
}

/// Get the private key that corresponds to the provided public key
fn get_private_key(
    parent_key: &ExtendedPrivateKey,
    requested_key: &ExtendedPublicKey,
) -> SignerResult<ExtendedPrivateKey> {
    let derived_key =
        parent_key.clone().derive_absolute_path(requested_key.get_derivation_path())?;
    if &derived_key.to_public_key() == requested_key {
        Ok(derived_key)
    } else {
        Err(SignerError::KeysNotInSameHierarchy)
    }
}

#[derive(Clone, Debug)]
pub struct SoftwareSignerProvider;

impl SoftwareSignerProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl SignerProvider for SoftwareSignerProvider {
    type S = SoftwareSigner;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, account_index: U31) -> Self::S {
        SoftwareSigner::new(chain_config, account_index)
    }
}

#[cfg(test)]
mod tests;
