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

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

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
        timelock::OutputTimeLock,
        tokens::{NftIssuance, TokenIssuance, TokenTotalSupply},
        AccountCommand, AccountSpending, ChainConfig, Destination, OutPointSourceId, TxInput,
        TxOutput,
    },
    primitives::Amount,
};
use crypto::key::{
    extended::{ExtendedPrivateKey, ExtendedPublicKey},
    hdkd::{chain_code::ChainCode, derivable::Derivable, u31::U31},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
    PrivateKey, Signature,
};
use itertools::Itertools;
use randomness::make_true_rng;
use serialization::Encode;
use trezor_client::{
    find_devices,
    protos::{
        MintlayerAccountCommandTxInput, MintlayerAccountTxInput, MintlayerBurnTxOutput,
        MintlayerChangeTokenAuhtority, MintlayerCreateDelegationIdTxOutput,
        MintlayerCreateStakePoolTxOutput, MintlayerDataDepositTxOutput,
        MintlayerDelegateStakingTxOutput, MintlayerFreezeToken,
        MintlayerIssueFungibleTokenTxOutput, MintlayerIssueNftTxOutput,
        MintlayerLockThenTransferTxOutput, MintlayerLockTokenSupply, MintlayerMintTokens,
        MintlayerOutputValue, MintlayerProduceBlockFromStakeTxOutput, MintlayerTokenTotalSupply,
        MintlayerTokenTotalSupplyType, MintlayerTxInput, MintlayerTxOutput, MintlayerUnfreezeToken,
        MintlayerUnmintTokens, MintlayerUtxoType,
    },
};
#[allow(clippy::all)]
use trezor_client::{
    protos::{MintlayerTransferTxOutput, MintlayerUtxoTxInput},
    Trezor,
};
use utils::ensure;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteUnlocked,
};
use wallet_types::{signature_status::SignatureStatus, AccountId};

use crate::{
    key_chain::{
        make_account_path, AccountKeyChainImplHardware, AccountKeyChains, FoundPubKey,
        MasterKeyChain,
    },
    Account, WalletResult,
};

use super::{Signer, SignerError, SignerProvider, SignerResult};

/// Signer errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum TrezorError {
    #[error("No connected Trezor device found")]
    NoDeviceFound,
}

pub struct TrezorSigner {
    chain_config: Arc<ChainConfig>,
    account_index: U31,
    client: Arc<Mutex<Trezor>>,
}

impl TrezorSigner {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        client: Arc<Mutex<Trezor>>,
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
                    if signature.is_empty() {
                        eprintln!("empty signature");
                        return Ok((None, SignatureStatus::NotSigned));
                    }

                    eprintln!("some signature pkh");
                    let pk =
                        key_chain.find_public_key(destination).expect("found").into_public_key();
                    eprintln!("pk {:?}", pk.encode());
                    let mut signature = signature.clone();
                    signature.insert(0, 0);
                    eprintln!("sig len {}", signature.len());
                    let sig = Signature::from_data(signature)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        sig.encode(),
                    ));

                    eprintln!("sig ok");
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

    fn to_trezor_output_msgs(&self, ptx: &PartiallySignedTransaction) -> Vec<MintlayerTxOutput> {
        let outputs = ptx
            .tx()
            .outputs()
            .iter()
            .map(|out| to_trezor_output_msg(&self.chain_config, out))
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
        let inputs = to_trezor_input_msgs(&ptx, key_chain, &self.chain_config);
        let outputs = self.to_trezor_output_msgs(&ptx);
        let utxos = to_trezor_utxo_msgs(&ptx, &self.chain_config);

        let new_signatures = self
            .client
            .lock()
            .expect("")
            .mintlayer_sign_tx(inputs, outputs, utxos)
            .expect("");
        eprintln!("new signatures: {new_signatures:?}");

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
                                eprintln!("valid signature {sighash:?}!!\n\n");
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

fn tx_output_value(out: &TxOutput) -> OutputValue {
    match out {
        TxOutput::Transfer(value, _)
        | TxOutput::LockThenTransfer(value, _, _)
        | TxOutput::Burn(value) => value.clone(),
        TxOutput::DelegateStaking(amount, _) => OutputValue::Coin(*amount),
        TxOutput::IssueNft(token_id, _, _) => {
            OutputValue::TokenV1(*token_id, Amount::from_atoms(1))
        }
        TxOutput::CreateStakePool(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DataDeposit(_) => OutputValue::Coin(Amount::ZERO),
    }
}

fn to_trezor_input_msgs(
    ptx: &PartiallySignedTransaction,
    key_chain: &impl AccountKeyChains,
    chain_config: &ChainConfig,
) -> Vec<MintlayerTxInput> {
    let inputs = ptx
        .tx()
        .inputs()
        .iter()
        .zip(ptx.input_utxos())
        .zip(ptx.destinations())
        .map(|((inp, utxo), dest)| match (inp, utxo, dest) {
            (TxInput::Utxo(outpoint), Some(utxo), Some(dest)) => {
                let mut inp_req = MintlayerUtxoTxInput::new();
                let id = match outpoint.source_id() {
                    OutPointSourceId::Transaction(id) => {
                        inp_req.set_type(MintlayerUtxoType::TRANSACTION);
                        id.to_hash().0
                    }
                    OutPointSourceId::BlockReward(id) => {
                        inp_req.set_type(MintlayerUtxoType::BLOCK);
                        id.to_hash().0
                    }
                };
                inp_req.set_prev_hash(id.to_vec());
                inp_req.set_prev_index(outpoint.output_index());
                match tx_output_value(utxo) {
                    OutputValue::Coin(amount) => {
                        let mut value = MintlayerOutputValue::new();
                        value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                        inp_req.value = Some(value).into();
                    }
                    OutputValue::TokenV1(token_id, amount) => {
                        let mut value = MintlayerOutputValue::new();
                        value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                        value.set_token_id(token_id.to_hash().as_bytes().to_vec());
                        inp_req.value = Some(value).into();
                    }
                    OutputValue::TokenV0(_) => {
                        panic!("token v0 unsuported");
                    }
                }

                inp_req.set_address(
                    Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
                );
                match key_chain.find_public_key(dest) {
                    Some(FoundPubKey::Hierarchy(xpub)) => {
                        inp_req.address_n = xpub
                            .get_derivation_path()
                            .as_slice()
                            .iter()
                            .map(|c| c.into_encoded_index())
                            .collect();
                    }
                    Some(FoundPubKey::Standalone(_)) => {
                        unimplemented!("standalone keys with trezor")
                    }
                    None => {}
                };

                let mut inp = MintlayerTxInput::new();
                inp.utxo = Some(inp_req).into();
                inp
            }
            (TxInput::Account(outpoint), _, Some(dest)) => {
                let mut inp_req = MintlayerAccountTxInput::new();
                inp_req.set_address(
                    Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
                );
                match key_chain.find_public_key(dest) {
                    Some(FoundPubKey::Hierarchy(xpub)) => {
                        inp_req.address_n = xpub
                            .get_derivation_path()
                            .as_slice()
                            .iter()
                            .map(|c| c.into_encoded_index())
                            .collect();
                    }
                    Some(FoundPubKey::Standalone(_)) => {
                        unimplemented!("standalone keys with trezor")
                    }
                    None => {}
                };
                inp_req.set_nonce(outpoint.nonce().value());
                match outpoint.account() {
                    AccountSpending::DelegationBalance(delegation_id, amount) => {
                        inp_req.set_delegation_id(delegation_id.to_hash().as_bytes().to_vec());
                        let mut value = MintlayerOutputValue::new();
                        value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                        inp_req.value = Some(value).into();
                    }
                }
                let mut inp = MintlayerTxInput::new();
                inp.account = Some(inp_req).into();
                inp
            }
            (TxInput::AccountCommand(nonce, command), _, Some(dest)) => {
                let mut inp_req = MintlayerAccountCommandTxInput::new();
                inp_req.set_address(
                    Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
                );
                match key_chain.find_public_key(dest) {
                    Some(FoundPubKey::Hierarchy(xpub)) => {
                        inp_req.address_n = xpub
                            .get_derivation_path()
                            .as_slice()
                            .iter()
                            .map(|c| c.into_encoded_index())
                            .collect();
                    }
                    Some(FoundPubKey::Standalone(_)) => {
                        unimplemented!("standalone keys with trezor")
                    }
                    None => {}
                };
                inp_req.set_nonce(nonce.value());
                match command {
                    AccountCommand::MintTokens(token_id, amount) => {
                        let mut req = MintlayerMintTokens::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());
                        req.set_amount(amount.into_atoms().to_be_bytes().to_vec());

                        inp_req.mint = Some(req).into();
                    }
                    AccountCommand::UnmintTokens(token_id) => {
                        let mut req = MintlayerUnmintTokens::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());

                        inp_req.unmint = Some(req).into();
                    }
                    AccountCommand::FreezeToken(token_id, unfreezable) => {
                        let mut req = MintlayerFreezeToken::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());
                        req.set_is_token_unfreezabe(unfreezable.as_bool());

                        inp_req.freeze_token = Some(req).into();
                    }
                    AccountCommand::UnfreezeToken(token_id) => {
                        let mut req = MintlayerUnfreezeToken::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());

                        inp_req.unfreeze_token = Some(req).into();
                    }
                    AccountCommand::LockTokenSupply(token_id) => {
                        let mut req = MintlayerLockTokenSupply::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());

                        inp_req.lock_token_supply = Some(req).into();
                    }
                    AccountCommand::ChangeTokenAuthority(token_id, dest) => {
                        let mut req = MintlayerChangeTokenAuhtority::new();
                        req.set_token_id(token_id.to_hash().as_bytes().to_vec());
                        req.set_destination(
                            Address::new(chain_config, dest.clone())
                                .expect("addressable")
                                .into_string(),
                        );

                        inp_req.change_token_authority = Some(req).into();
                    }
                }
                let mut inp = MintlayerTxInput::new();
                inp.account_command = Some(inp_req).into();
                inp
            }
            (TxInput::Utxo(_) | TxInput::Account(_) | TxInput::AccountCommand(_, _), _, _) => {
                unimplemented!("accounting not supported yet with trezor")
            }
        })
        .collect();
    inputs
}

fn to_trezor_utxo_msgs(
    ptx: &PartiallySignedTransaction,
    chain_config: &ChainConfig,
) -> BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTxOutput>> {
    let utxos = ptx.input_utxos().iter().zip(ptx.tx().inputs()).fold(
        BTreeMap::new(),
        |mut map: BTreeMap<[u8; 32], BTreeMap<u32, _>>, (utxo, inp)| {
            match (inp, utxo) {
                (TxInput::Utxo(outpoint), Some(utxo)) => {
                    let id = match outpoint.source_id() {
                        OutPointSourceId::Transaction(id) => id.to_hash().0,
                        OutPointSourceId::BlockReward(id) => id.to_hash().0,
                    };
                    let out = to_trezor_output_msg(chain_config, utxo);
                    map.entry(id).or_default().insert(outpoint.output_index(), out);
                }
                (TxInput::Utxo(_), None) => unimplemented!("missing utxo"),
                (TxInput::Account(_) | TxInput::AccountCommand(_, _), Some(_)) => {
                    panic!("can't have accounts as UTXOs")
                }
                (TxInput::Account(_) | TxInput::AccountCommand(_, _), _) => {}
            }
            map
        },
    );
    utxos
}

fn set_value(value: &OutputValue, out_req: &mut MintlayerTransferTxOutput) {
    match value {
        OutputValue::Coin(amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            out_req.value = Some(value).into();
        }
        OutputValue::TokenV1(token_id, amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            value.set_token_id(token_id.to_hash().as_bytes().to_vec());
            out_req.value = Some(value).into();
        }
        OutputValue::TokenV0(_) => {
            panic!("token v0 unsuported");
        }
    };
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

fn to_trezor_output_msg(chain_config: &ChainConfig, out: &TxOutput) -> MintlayerTxOutput {
    match out {
        TxOutput::Transfer(value, dest) => {
            let mut out_req = MintlayerTransferTxOutput::new();
            set_value(value, &mut out_req);
            out_req.set_address(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );

            let mut out = MintlayerTxOutput::new();
            out.transfer = Some(out_req).into();
            out
        }
        TxOutput::LockThenTransfer(value, dest, lock) => {
            let mut out_req = MintlayerLockThenTransferTxOutput::new();
            match value {
                OutputValue::Coin(amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV1(token_id, amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    value.set_token_id(token_id.to_hash().as_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV0(_) => {
                    panic!("token v0 unsuported");
                }
            };
            out_req.set_address(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );

            let mut lock_req = trezor_client::protos::MintlayerOutputTimeLock::new();
            match lock {
                OutputTimeLock::UntilTime(time) => {
                    lock_req.set_until_time(time.as_int_seconds());
                }
                OutputTimeLock::UntilHeight(height) => {
                    lock_req.set_until_height(height.into_int());
                }
                OutputTimeLock::ForSeconds(sec) => {
                    lock_req.set_for_seconds(*sec);
                }
                OutputTimeLock::ForBlockCount(count) => {
                    lock_req.set_for_block_count(*count);
                }
            }
            out_req.lock = Some(lock_req).into();

            let mut out = MintlayerTxOutput::new();
            out.lock_then_transfer = Some(out_req).into();
            out
        }
        TxOutput::Burn(value) => {
            let mut out_req = MintlayerBurnTxOutput::new();
            match value {
                OutputValue::Coin(amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV1(token_id, amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    value.set_token_id(token_id.to_hash().as_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV0(_) => {
                    panic!("token v0 unsuported");
                }
            };

            let mut out = MintlayerTxOutput::new();
            out.burn = Some(out_req).into();
            out
        }
        TxOutput::CreateDelegationId(dest, pool_id) => {
            let mut out_req = MintlayerCreateDelegationIdTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            let mut out = MintlayerTxOutput::new();
            out.create_delegation_id = Some(out_req).into();
            out
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            let mut out_req = MintlayerDelegateStakingTxOutput::new();
            out_req.set_delegation_id(delegation_id.to_hash().as_bytes().to_vec());
            out_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            let mut out = MintlayerTxOutput::new();
            out.delegate_staking = Some(out_req).into();
            out
        }
        TxOutput::CreateStakePool(pool_id, pool_data) => {
            let mut out_req = MintlayerCreateStakePoolTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());

            out_req.set_pledge(pool_data.pledge().into_atoms().to_be_bytes().to_vec());
            out_req.set_staker(
                Address::new(chain_config, pool_data.staker().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req.set_decommission_key(
                Address::new(chain_config, pool_data.decommission_key().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req.set_vrf_public_key(
                Address::new(chain_config, pool_data.vrf_public_key().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req
                .set_cost_per_block(pool_data.cost_per_block().into_atoms().to_be_bytes().to_vec());
            out_req.set_margin_ratio_per_thousand(
                pool_data.margin_ratio_per_thousand().as_per_thousand_int() as u32,
            );

            let mut out = MintlayerTxOutput::new();
            out.create_stake_pool = Some(out_req).into();
            out
        }
        TxOutput::ProduceBlockFromStake(dest, pool_id) => {
            let mut out_req = MintlayerProduceBlockFromStakeTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            let mut out = MintlayerTxOutput::new();
            out.produce_block_from_stake = Some(out_req).into();
            out
        }
        TxOutput::IssueFungibleToken(token_data) => {
            let mut out_req = MintlayerIssueFungibleTokenTxOutput::new();

            match token_data.as_ref() {
                TokenIssuance::V1(data) => {
                    out_req.set_authority(
                        Address::new(chain_config, data.authority.clone())
                            .expect("addressable")
                            .into_string(),
                    );
                    out_req.set_token_ticker(data.token_ticker.clone());
                    out_req.set_metadata_uri(data.metadata_uri.clone());
                    out_req.set_number_of_decimals(data.number_of_decimals as u32);
                    out_req.set_is_freezable(data.is_freezable.as_bool());
                    let mut total_supply = MintlayerTokenTotalSupply::new();
                    match data.total_supply {
                        TokenTotalSupply::Lockable => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::LOCKABLE)
                        }
                        TokenTotalSupply::Unlimited => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::UNLIMITED)
                        }
                        TokenTotalSupply::Fixed(amount) => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::FIXED);
                            total_supply
                                .set_fixed_amount(amount.into_atoms().to_be_bytes().to_vec());
                        }
                    }
                    out_req.total_supply = Some(total_supply).into();
                }
            };

            let mut out = MintlayerTxOutput::new();
            out.issue_fungible_token = Some(out_req).into();
            out
        }
        TxOutput::IssueNft(token_id, nft_data, dest) => {
            let mut out_req = MintlayerIssueNftTxOutput::new();
            out_req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            match nft_data.as_ref() {
                NftIssuance::V0(data) => {
                    //
                    out_req.set_name(data.metadata.name.clone());
                    out_req.set_ticker(data.metadata.ticker().clone());
                    out_req.set_icon_uri(
                        data.metadata
                            .icon_uri()
                            .as_ref()
                            .as_ref()
                            .map(|x| x.clone())
                            .unwrap_or_default(),
                    );
                    out_req.set_media_uri(
                        data.metadata
                            .media_uri()
                            .as_ref()
                            .as_ref()
                            .map(|x| x.clone())
                            .unwrap_or_default(),
                    );
                    out_req.set_media_hash(data.metadata.media_hash().clone());
                    out_req.set_additional_metadata_uri(
                        data.metadata
                            .additional_metadata_uri()
                            .as_ref()
                            .as_ref()
                            .map(|x| x.clone())
                            .unwrap_or_default(),
                    );
                    out_req.set_description(data.metadata.description.clone());
                    if let Some(creator) = data.metadata.creator() {
                        out_req.set_creator(
                            Address::new(
                                chain_config,
                                Destination::PublicKey(creator.public_key.clone()),
                            )
                            .expect("addressable")
                            .into_string(),
                        );
                    }
                }
            };
            let mut out = MintlayerTxOutput::new();
            out.issue_nft = Some(out_req).into();
            out
        }
        TxOutput::DataDeposit(data) => {
            let mut out_req = MintlayerDataDepositTxOutput::new();
            out_req.set_data(data.clone());
            let mut out = MintlayerTxOutput::new();
            out.data_deposit = Some(out_req).into();
            out
        }
    }
}

#[derive(Clone)]
pub struct TrezorSignerProvider {
    client: Arc<Mutex<Trezor>>,
}

impl std::fmt::Debug for TrezorSignerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrezorSignerProvider")
    }
}

impl TrezorSignerProvider {
    pub fn new() -> Result<Self, TrezorError> {
        let mut devices = find_devices(false);
        ensure!(!devices.is_empty(), TrezorError::NoDeviceFound);

        let client = devices.pop().unwrap().connect().unwrap();

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }
}

impl SignerProvider for TrezorSignerProvider {
    type S = TrezorSigner;
    type K = AccountKeyChainImplHardware;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, account_index: U31) -> Self::S {
        TrezorSigner::new(chain_config, account_index, self.client.clone())
    }

    fn make_new_account(
        &mut self,
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        name: Option<String>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
    ) -> WalletResult<Account<Self::K>> {
        eprintln!(
            "coin type in new acc trezor: {:?}",
            chain_config.bip44_coin_type().get_index()
        );
        let derivation_path = make_account_path(&chain_config, account_index);
        let account_path =
            derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect();

        eprintln!("account path {account_path:?}");

        let xpub = self
            .client
            .lock()
            .expect("")
            .mintlayer_get_public_key(account_path)
            .expect("")
            .ok()
            .expect("");

        let chain_code = ChainCode::from(xpub.chain_code.0);
        let account_pubkey = Secp256k1ExtendedPublicKey::from_hardware_wallet(
            derivation_path,
            chain_code,
            Secp256k1PublicKey::from_bytes(&xpub.public_key.serialize()).expect(""),
        );
        let account_pubkey = ExtendedPublicKey::from_hardware_public_key(account_pubkey);

        let lookahead_size = db_tx.get_lookahead_size()?;

        let key_chain = AccountKeyChainImplHardware::new_from_hardware_key(
            chain_config.clone(),
            db_tx,
            account_pubkey,
            account_index,
            lookahead_size,
        )?;

        Account::new(chain_config, db_tx, key_chain, name)
    }

    fn load_account_from_database(
        &self,
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> WalletResult<Account<Self::K>> {
        Account::load_from_database(chain_config, db_tx, id)
    }
}

#[cfg(test)]
mod tests;
