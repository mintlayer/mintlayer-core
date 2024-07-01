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

use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};

use common::{
    address::Address,
    chain::{
        output_value::OutputValue,
        partially_signed_transaction::PartiallySignedTransaction,
        signature::{
            inputsig::{
                arbitrary_message::ArbitraryMessageSignature,
                authorize_pubkey_spend::AuthorizedPublicKeySpend,
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
        },
        ChainConfig, Destination, OutPointSourceId, TxInput, TxOutput,
    },
};
use crypto::key::{
    extended::{ExtendedPrivateKey, ExtendedPublicKey},
    hdkd::{derivable::Derivable, u31::U31},
    PrivateKey, Signature,
};
use itertools::Itertools;
use randomness::make_true_rng;
use serialization::Encode;
#[allow(clippy::all)]
use trezor_client::{
    protos::{MintlayerTransferTxOutput, MintlayerUtxoTxInput},
    Trezor,
};
use wallet_storage::{WalletStorageReadUnlocked, WalletStorageWriteUnlocked};
use wallet_types::signature_status::SignatureStatus;

use crate::{
    key_chain::{make_account_path, AccountKeyChains, FoundPubKey, MasterKeyChain},
    Account, WalletResult,
};

use super::{Signer, SignerError, SignerProvider, SignerResult};

pub struct TrezorSigner {
    chain_config: Arc<ChainConfig>,
    account_index: U31,
    client: Rc<RefCell<Trezor>>,
}

impl TrezorSigner {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        client: Rc<RefCell<Trezor>>,
    ) -> Self {
        Self {
            chain_config,
            account_index,
            client,
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

    fn make_signature(
        &self,
        signature: &Option<Vec<u8>>,
        destination: &Destination,
        sighash_type: SigHashType,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)> {
        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKeyHash(_) => {
                if let Some(signature) = signature {
                    eprintln!("some signature pkh");
                    let pk =
                        key_chain.find_public_key(destination).expect("found").into_public_key();
                    eprintln!("pk {:?}", pk.encode());
                    let mut signature = signature.clone();
                    signature.insert(0, 0);
                    let sig = Signature::from_data(signature)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        sig.encode(),
                    ));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    eprintln!("empty signature");
                    Ok((None, SignatureStatus::NotSigned))
                }
            }
            Destination::PublicKey(_) => {
                if let Some(signature) = signature {
                    eprintln!("some signature pk");
                    let mut signature = signature.clone();
                    signature.insert(0, 0);
                    let sig = Signature::from_data(signature)?;
                    let sig = AuthorizedPublicKeySpend::new(sig);
                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        sig.encode(),
                    ));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    eprintln!("empty signature");
                    Ok((None, SignatureStatus::NotSigned))
                }
            }
            Destination::ClassicMultisig(_) => {
                if let Some(_challenge) = key_chain.find_multisig_challenge(destination) {
                    unimplemented!("add support for multisig in Trezor")
                }

                Ok((None, SignatureStatus::NotSigned))
            }
            Destination::ScriptHash(_) => Ok((None, SignatureStatus::NotSigned)),
        }
    }

    fn to_trezor_output_msgs(
        &self,
        ptx: &PartiallySignedTransaction,
    ) -> Vec<MintlayerTransferTxOutput> {
        let outputs = ptx
            .tx()
            .outputs()
            .iter()
            .map(|out| match out {
                TxOutput::Transfer(value, dest) => match value {
                    OutputValue::Coin(amount) => {
                        let mut out_req = MintlayerTransferTxOutput::new();
                        out_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                        out_req.set_address(
                            Address::new(&self.chain_config, dest.clone())
                                .expect("addressable")
                                .into_string(),
                        );
                        out_req
                    }
                    _ => unimplemented!("support transfer of tokens in trezor"),
                },
                _ => unimplemented!("support other output types in trezor"),
            })
            .collect();
        outputs
    }
}

impl Signer for TrezorSigner {
    fn sign_tx(
        &mut self,
        ptx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
        _db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        let inputs = to_trezor_input_msgs(&ptx);
        let outputs = self.to_trezor_output_msgs(&ptx);
        let utxos = to_trezor_utxo_msgs(&ptx, key_chain);

        let new_signatures =
            self.client.borrow_mut().mintlayer_sign_tx(inputs, outputs, utxos).expect("");

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
                                unimplemented!("add support for multisig to Trezor");
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
                None => match (destination, new_signatures.get(i)) {
                    (Some(destination), Some(sig)) => {
                        let sighash_type =
                            SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
                        eprintln!("making sig for {i}");
                        let (sig, status) =
                            self.make_signature(sig, destination, sighash_type, key_chain)?;
                        Ok((sig, SignatureStatus::NotSigned, status))
                    }
                    (Some(_) | None, None) | (None, Some(_)) => {
                        eprintln!("no signature!");
                        Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned))
                    }
                },
            })
            .collect::<Result<Vec<_>, SignerError>>()?
            .into_iter()
            .multiunzip();

        Ok((ptx.with_witnesses(witnesses), prev_statuses, new_statuses))
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

fn to_trezor_input_msgs(ptx: &PartiallySignedTransaction) -> Vec<MintlayerUtxoTxInput> {
    let inputs = ptx
        .tx()
        .inputs()
        .iter()
        .zip(ptx.input_utxos())
        .map(|(inp, utxo)| match (inp, utxo) {
            (TxInput::Utxo(outpoint), Some(TxOutput::Transfer(value, _))) => {
                let mut inp_req = MintlayerUtxoTxInput::new();
                let id = match outpoint.source_id() {
                    OutPointSourceId::Transaction(id) => id.to_hash().0,
                    OutPointSourceId::BlockReward(id) => id.to_hash().0,
                };
                inp_req.set_prev_hash(id.to_vec());
                inp_req.set_prev_index(outpoint.output_index());
                match value {
                    OutputValue::Coin(amount) => {
                        inp_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    }
                    OutputValue::TokenV1(_, _) | OutputValue::TokenV0(_) => {
                        unimplemented!("support for tokens")
                    }
                }

                inp_req
            }
            (TxInput::Utxo(_) | TxInput::Account(_) | TxInput::AccountCommand(_, _), _) => {
                unimplemented!("accounting not supported yet with trezor")
            }
        })
        .collect();
    inputs
}

fn to_trezor_utxo_msgs(
    ptx: &PartiallySignedTransaction,
    key_chain: &impl AccountKeyChains,
) -> BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTransferTxOutput>> {
    let utxos = ptx
        .input_utxos()
        .iter()
        .zip(ptx.tx().inputs())
        .filter_map(|(utxo, inp)| utxo.as_ref().map(|utxo| (utxo, inp)))
        .fold(
            BTreeMap::new(),
            |mut map: BTreeMap<[u8; 32], BTreeMap<u32, _>>, (utxo, inp)| {
                match (inp, utxo) {
                    (TxInput::Utxo(outpoint), TxOutput::Transfer(value, dest)) => {
                        let mut out_req = MintlayerTransferTxOutput::new();
                        match value {
                            OutputValue::Coin(amount) => {
                                out_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                            }
                            OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => {
                                unimplemented!("support tokens in trezor")
                            }
                        };

                        out_req.address_n = match key_chain.find_public_key(dest) {
                            Some(FoundPubKey::Hierarchy(xpub)) => xpub
                                .get_derivation_path()
                                .as_slice()
                                .iter()
                                .map(|c| c.into_encoded_index())
                                .collect(),
                            Some(FoundPubKey::Standalone(_)) => {
                                unimplemented!("standalone keys with trezor")
                            }
                            None => unimplemented!("external keys with trezor"),
                        };

                        let id = match outpoint.source_id() {
                            OutPointSourceId::Transaction(id) => id.to_hash().0,
                            OutPointSourceId::BlockReward(id) => id.to_hash().0,
                        };

                        map.entry(id).or_default().insert(outpoint.output_index(), out_req);
                    }
                    (TxInput::Utxo(_), _) => unimplemented!("support other utxo types"),
                    (TxInput::Account(_) | TxInput::AccountCommand(_, _), _) => {
                        panic!("can't have accounts as UTXOs")
                    }
                }
                map
            },
        );
    utxos
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

#[derive(Clone)]
pub struct TrezorSignerProvider {
    client: Rc<RefCell<Trezor>>,
}

impl std::fmt::Debug for TrezorSignerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrezorSignerProvider")
    }
}

impl TrezorSignerProvider {
    pub fn new(client: Trezor) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
        }
    }
}

impl SignerProvider for TrezorSignerProvider {
    type S = TrezorSigner;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, account_index: U31) -> Self::S {
        TrezorSigner::new(chain_config, account_index, self.client.clone())
    }

    fn make_new_account(
        &mut self,
        _chain_config: Arc<ChainConfig>,
        _account_index: U31,
        _name: Option<String>,
        _db_tx: &mut impl WalletStorageWriteUnlocked,
    ) -> WalletResult<Account> {
        unimplemented!("hehe");
    }
}

#[cfg(test)]
mod tests;
