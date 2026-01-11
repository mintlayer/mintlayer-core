// Copyright (c) 2025 RBB S.r.l
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

mod ledger_messages;

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    key_chain::{make_account_path, AccountKeyChainImplHardware, AccountKeyChains, FoundPubKey},
    signer::{
        ledger_signer::ledger_messages::{
            check_current_app, get_extended_public_key, get_extended_public_key_raw,
            sign_challenge, sign_tx,
        },
        utils::{is_htlc_utxo, produce_uniparty_signature_for_input},
        Signer, SignerError, SignerProvider, SignerResult,
    },
    Account, WalletResult,
};
use common::{
    chain::{
        config::ChainType,
        signature::{
            inputsig::{
                arbitrary_message::ArbitraryMessageSignature,
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                authorize_pubkey_spend::AuthorizedPublicKeySpend,
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                classical_multisig::{
                    authorize_classical_multisig::{
                        sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                        ClassicalMultisigCompletionStatus,
                    },
                    multisig_partial_signature::{self, PartiallySignedMultisigChallenge},
                },
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
            DestinationSigError,
        },
        AccountCommand, ChainConfig, Destination, OrderAccountCommand, SignedTransactionIntent,
        Transaction, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Idable, H256},
    primitives_converters::TryConvertInto as _,
};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{derivable::Derivable, u31::U31},
    signature::SignatureKind,
    PrivateKey, SigAuxDataProvider, Signature, SignatureError,
};
use serialization::Encode;
use utils::ensure;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteUnlocked,
};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    hw_data::{HardwareWalletFullInfo, LedgerData, LedgerFullInfo, LedgerModel},
    partially_signed_transaction::{
        PartiallySignedTransaction, PtxAdditionalInfo, TokensAdditionalInfo,
    },
    signature_status::SignatureStatus,
    AccountId,
};

use async_trait::async_trait;
use itertools::{izip, Itertools};
use ledger_lib::{info::Model, Exchange, Filters, LedgerHandle, LedgerProvider, Transport};
use mintlayer_ledger_messages::{
    AdditionalOrderInfo, AdditionalUtxoInfo, AddrType, Bip32Path as LedgerBip32Path, CoinType,
    InputAddressPath as LedgerInputAddressPath, SighashInputCommitment as LSighashInputCommitment,
    Signature as LedgerSignature, TxInputReq, TxInputWithAdditionalInfo, TxOutputReq,
};
use randomness::make_true_rng;
use tokio::sync::Mutex;

/// Signer errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum LedgerError {
    #[error("No connected Ledger device found")]
    NoDeviceFound,
    #[error("Connected to an unknown Ledger device model")]
    UnknownModel,
    #[error("Device timeout")]
    DeviceTimeout,
    #[error("A different app is currently open on your Ledger device: \"{0}\". Please close it and open the Mintlayer app instead.")]
    DifferentActiveApp(String),
    #[error("Received an invalid response from the Ledger device")]
    InvalidResponse,
    #[error("Received an error response from the Ledger device: {0}")]
    ErrorResponse(String),
    #[error("Device error: {0}")]
    DeviceError(String),
    #[error("Missing hardware wallet data in database")]
    MissingHardwareWalletData,
    #[error("Invalid public key returned from Ledger")]
    InvalidKey,
    #[error("The file being loaded is a software wallet and cannot be used with the connected Ledger wallet")]
    WalletFileIsSoftwareWallet,
    #[error("Public keys mismatch - wrong device or passphrase")]
    HardwareWalletDifferentMnemonicOrPassphrase,
    #[error("A multisig signature was returned for a single address from Device")]
    MultisigSignatureReturned,
    #[error("Multiple signatures returned for a single address from Device")]
    MultipleSignaturesReturned,
    #[error("Missing multisig index for signature returned from Device")]
    MissingMultisigIndexForSignature,
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Input commitments version 1 is not supported by the Ledger app")]
    InputCommitmentVersion1NotSupported,
}

impl From<ledger_lib::Error> for LedgerError {
    fn from(value: ledger_lib::Error) -> Self {
        Self::DeviceError(value.to_string())
    }
}

struct StandaloneInput {
    multisig_idx: Option<u32>,
    private_key: PrivateKey,
}

type StandaloneInputs = BTreeMap</*input index*/ u32, Vec<StandaloneInput>>;

#[async_trait]
pub trait LedgerFinder {
    type Ledger;

    async fn find_ledger_device_from_db<T: WalletStorageReadLocked + Send>(
        &self,
        db_tx: &mut T,
        chain_config: Arc<ChainConfig>,
    ) -> SignerResult<(Self::Ledger, LedgerData)>;
}

pub struct LedgerSigner<L, P> {
    chain_config: Arc<ChainConfig>,
    client: Arc<Mutex<L>>,
    sig_aux_data_provider: std::sync::Mutex<Box<dyn SigAuxDataProvider + Send>>,
    provider: P,
}

impl<L, P> LedgerSigner<L, P>
where
    L: Exchange + Send,
    P: LedgerFinder<Ledger = L>,
{
    pub fn new(chain_config: Arc<ChainConfig>, client: Arc<Mutex<L>>, provider: P) -> Self {
        Self::new_with_sig_aux_data_provider(
            chain_config,
            client,
            Box::new(make_true_rng()),
            provider,
        )
    }

    pub fn new_with_sig_aux_data_provider(
        chain_config: Arc<ChainConfig>,
        client: Arc<Mutex<L>>,
        sig_aux_data_provider: Box<dyn SigAuxDataProvider + Send>,
        provider: P,
    ) -> Self {
        Self {
            chain_config,
            client,
            sig_aux_data_provider: std::sync::Mutex::new(sig_aux_data_provider),
            provider,
        }
    }

    /// Tries to confirm the running app name is still matching Mintlayer app
    /// Also waits after a signing operation for the device to start listening to new instructions
    ///
    /// If the operation fails due to an USB error (which may indicate a lost connection to the device),
    /// the function will attempt to reconnect to the Ledger device once before returning an error.
    async fn check_session<T: WalletStorageReadLocked + Send>(
        &mut self,
        db_tx: &mut T,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<()> {
        let mut client = self.client.lock().await;
        // Try and wait around 50 * 100ms for the screen to clear after a signing operation ends
        let mut num_tries = 50;
        let derivation_path = make_account_path(&self.chain_config, key_chain.account_index());
        let coin_type = to_ledger_chain_type(&self.chain_config);
        loop {
            match get_extended_public_key_raw(&mut *client, coin_type, &derivation_path).await {
                Ok(_) => {
                    check_public_keys_against_key_chain(
                        db_tx,
                        &mut *client,
                        key_chain,
                        &self.chain_config,
                    )
                    .await?;
                    return Ok(());
                }
                // After finishing a signing operation the device shows a status success/failed
                // At those times any command sent is not handles so waiting for a response will
                // just timeout
                Err(ledger_lib::Error::Timeout) => {
                    num_tries -= 1;
                    if num_tries > 0 {
                        continue;
                    } else {
                        return Err(SignerError::LedgerError(LedgerError::DeviceTimeout));
                    }
                }
                // In case of a communication error try to reconnect, and try again
                Err(
                    ledger_lib::Error::Hid(_)
                    | ledger_lib::Error::Tcp(_)
                    | ledger_lib::Error::Ble(_),
                ) => {
                    let (mut new_client, _data) = self
                        .provider
                        .find_ledger_device_from_db(db_tx, self.chain_config.clone())
                        .await?;

                    check_public_keys_against_key_chain(
                        db_tx,
                        &mut new_client,
                        key_chain,
                        &self.chain_config,
                    )
                    .await?;

                    *client = new_client;
                    return Ok(());
                }
                Err(err) => return Err(SignerError::LedgerError(err.into())),
            }
        }
    }

    /// Attempts to perform an operation on the Ledger client.
    ///
    /// If the operation fails due to an USB error (which may indicate a lost connection to the device),
    /// the function will attempt to reconnect to the Ledger device once before returning an error.
    async fn perform_ledger_operation<F, R, T: WalletStorageReadLocked + Send>(
        &mut self,
        operation: F,
        db_tx: &mut T,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<R>
    where
        F: AsyncFnOnce(&mut L) -> Result<R, SignerError>,
    {
        self.check_session(db_tx, key_chain).await?;

        let mut client = self.client.lock().await;
        operation(&mut client).await
    }

    #[allow(clippy::too_many_arguments)]
    fn make_signature<'a, 'b, MakeWitnessFn, StandaloneSignerFn>(
        &self,
        signatures: &[LedgerSignature],
        standalone_inputs: &'a [StandaloneInput],
        destination: &'b Destination,
        sighash_type: SigHashType,
        sighash: H256,
        key_chain: &impl AccountKeyChains,
        make_witness: MakeWitnessFn,
        sign_with_standalone_private_key: StandaloneSignerFn,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)>
    where
        MakeWitnessFn: Fn(StandardInputSignature) -> InputWitness,
        StandaloneSignerFn: Fn(&'a StandaloneInput, &'b Destination) -> SignerResult<InputWitness>,
    {
        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKeyHash(_) => {
                if let Some(signature) = single_signature(signatures)? {
                    let pk = key_chain
                        .find_public_key(destination)
                        .ok_or(SignerError::DestinationNotFromThisWallet)?
                        .into_public_key();
                    let sig = Signature::from_raw_data(
                        signature.signature,
                        SignatureKind::Secp256k1Schnorr,
                    )
                    .map_err(LedgerError::SignatureError)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    StandardInputSignature::new(sighash_type, sig.encode()).verify_signature(
                        &self.chain_config,
                        destination,
                        &sighash,
                    )?;
                    let sig = make_witness(StandardInputSignature::new(sighash_type, sig.encode()));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    let standalone = match standalone_inputs {
                        [] => return Ok((None, SignatureStatus::NotSigned)),
                        [standalone] => standalone,
                        _ => return Err(LedgerError::MultisigSignatureReturned.into()),
                    };

                    let sig = sign_with_standalone_private_key(standalone, destination)?;
                    Ok((Some(sig), SignatureStatus::FullySigned))
                }
            }
            Destination::PublicKey(_) => {
                if let Some(signature) = single_signature(signatures)? {
                    let sig = Signature::from_raw_data(
                        signature.signature,
                        SignatureKind::Secp256k1Schnorr,
                    )
                    .map_err(LedgerError::SignatureError)?;
                    let sig = AuthorizedPublicKeySpend::new(sig);
                    StandardInputSignature::new(sighash_type, sig.encode()).verify_signature(
                        &self.chain_config,
                        destination,
                        &sighash,
                    )?;
                    let sig = make_witness(StandardInputSignature::new(sighash_type, sig.encode()));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    let standalone = match standalone_inputs {
                        [] => return Ok((None, SignatureStatus::NotSigned)),
                        [standalone] => standalone,
                        _ => return Err(LedgerError::MultisigSignatureReturned.into()),
                    };

                    let sig = sign_with_standalone_private_key(standalone, destination)?;
                    Ok((Some(sig), SignatureStatus::FullySigned))
                }
            }
            Destination::ClassicMultisig(_) => {
                if let Some(challenge) = key_chain.find_multisig_challenge(destination) {
                    let (current_signatures, status) = self.update_and_check_multisig(
                        signatures,
                        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone()),
                        sighash,
                    )?;

                    let (current_signatures, status) = self.sign_with_standalone_private_keys(
                        current_signatures,
                        standalone_inputs,
                        status,
                        sighash,
                    )?;

                    let sig = make_witness(StandardInputSignature::new(
                        sighash_type,
                        current_signatures.encode(),
                    ));
                    return Ok((Some(sig), status));
                }

                Ok((None, SignatureStatus::NotSigned))
            }
            Destination::ScriptHash(_) => Ok((None, SignatureStatus::NotSigned)),
        }
    }

    fn to_ledger_output_msgs(
        &self,
        ptx: &PartiallySignedTransaction,
    ) -> SignerResult<Vec<TxOutputReq>> {
        ptx.tx()
            .outputs()
            .iter()
            .map(|out| {
                Ok(TxOutputReq {
                    out: out.clone().try_convert_into()?,
                })
            })
            .collect()
    }

    fn check_multisig_signature_status(
        &self,
        sighash: H256,
        current_signatures: &AuthorizedClassicalMultisigSpend,
    ) -> Result<SignatureStatus, SignerError> {
        let msg = sighash.encode();
        let verifier = PartiallySignedMultisigChallenge::from_partial(
            &self.chain_config,
            &msg,
            current_signatures,
        )?;
        let status = match verifier.verify_signatures(&self.chain_config)? {
            multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
                SignatureStatus::FullySigned
            }
            multisig_partial_signature::SigsVerifyResult::Incomplete => {
                let challenge = current_signatures.challenge();
                SignatureStatus::PartialMultisig {
                    required_signatures: challenge.min_required_signatures(),
                    num_signatures: current_signatures.signatures().len() as u8,
                }
            }
            multisig_partial_signature::SigsVerifyResult::Invalid => {
                SignatureStatus::InvalidSignature
            }
        };
        Ok(status)
    }

    fn update_and_check_multisig(
        &self,
        signatures: &[LedgerSignature],
        mut current_signatures: AuthorizedClassicalMultisigSpend,
        sighash: H256,
    ) -> SignerResult<(AuthorizedClassicalMultisigSpend, SignatureStatus)> {
        for sig in signatures {
            let idx = sig.multisig_idx.ok_or(LedgerError::MissingMultisigIndexForSignature)?;
            let sig = Signature::from_raw_data(sig.signature, SignatureKind::Secp256k1Schnorr)
                .map_err(LedgerError::SignatureError)?;
            current_signatures.add_signature(idx as u8, sig);
        }

        let status = self.check_multisig_signature_status(sighash, &current_signatures)?;

        Ok((current_signatures, status))
    }

    fn sign_with_standalone_private_keys(
        &self,
        current_signatures: AuthorizedClassicalMultisigSpend,
        standalone_inputs: &[StandaloneInput],
        new_status: SignatureStatus,
        sighash: H256,
    ) -> SignerResult<(AuthorizedClassicalMultisigSpend, SignatureStatus)> {
        let challenge = current_signatures.challenge().clone();

        standalone_inputs.iter().try_fold(
            (current_signatures, new_status),
            |(mut current_signatures, mut status), inp| -> SignerResult<_> {
                if status == SignatureStatus::FullySigned {
                    return Ok((current_signatures, status));
                }

                let key_index =
                    inp.multisig_idx.ok_or(LedgerError::MissingMultisigIndexForSignature)?;
                let res = sign_classical_multisig_spending(
                    &self.chain_config,
                    key_index as u8,
                    &inp.private_key,
                    &challenge,
                    &sighash,
                    current_signatures,
                    self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut(),
                )
                .map_err(DestinationSigError::ClassicalMultisigSigningFailed)?;

                match res {
                    ClassicalMultisigCompletionStatus::Complete(signatures) => {
                        current_signatures = signatures;
                        status = SignatureStatus::FullySigned;
                    }
                    ClassicalMultisigCompletionStatus::Incomplete(signatures) => {
                        current_signatures = signatures;
                        status = SignatureStatus::PartialMultisig {
                            required_signatures: challenge.min_required_signatures(),
                            num_signatures: current_signatures.signatures().len() as u8,
                        };
                    }
                };

                Ok((current_signatures, status))
            },
        )
    }
}

#[async_trait]
impl<L, P> Signer for LedgerSigner<L, P>
where
    L: Exchange + Send,
    P: Send + Sync + LedgerFinder<Ledger = L>,
{
    async fn sign_tx(
        &mut self,
        ptx: PartiallySignedTransaction,
        _tokens_additional_info: &TokensAdditionalInfo,
        key_chain: &(impl AccountKeyChains + Sync),
        mut db_tx: impl WalletStorageReadUnlocked + Send,
        block_height: BlockHeight,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        let (inputs, standalone_inputs) = to_ledger_input_msgs(&ptx, key_chain, &db_tx)?;
        let input_commitments = to_ledger_input_commitments_reqs(&ptx)?;
        let outputs = self.to_ledger_output_msgs(&ptx)?;
        let coin_type = to_ledger_chain_type(&self.chain_config);

        let input_commitment_version = self
            .chain_config
            .chainstate_upgrades()
            .version_at_height(block_height)
            .1
            .sighash_input_commitment_version();
        // input_commitments V0 is not implemented as it will likely not be needed by the time
        // Ledger support is released
        ensure!(
            input_commitment_version == common::chain::SighashInputCommitmentVersion::V1,
            LedgerError::InputCommitmentVersion1NotSupported
        );

        let new_signatures = self
            .perform_ledger_operation(
                async move |client| {
                    sign_tx(client, coin_type, inputs, input_commitments, outputs).await
                },
                &mut db_tx,
                key_chain,
            )
            .await?;

        let input_commitments =
            ptx.make_sighash_input_commitments_at_height(&self.chain_config, block_height)?;

        let (witnesses, prev_statuses, new_statuses) = itertools::process_results(
            izip!(
                ptx.witnesses(),
                ptx.input_utxos(),
                ptx.destinations(),
                ptx.htlc_secrets()
            )
            .enumerate()
            .map(|(input_index, (witness, input_utxo, destination, htlc_secret))| -> SignerResult<_> {
                let is_htlc_input = input_utxo.as_ref().is_some_and(is_htlc_utxo);
                let make_witness = |sig: StandardInputSignature| {
                    let sig = if is_htlc_input {
                        let sighash_type = sig.sighash_type();
                        let spend = if let Some(htlc_secret) = htlc_secret {
                            AuthorizedHashedTimelockContractSpend::Spend(
                                htlc_secret.clone(),
                                sig.into_raw_signature(),
                            )
                        } else {
                            AuthorizedHashedTimelockContractSpend::Refund(sig.into_raw_signature())
                        };

                        let serialized_spend = spend.encode();
                        StandardInputSignature::new(sighash_type, serialized_spend)
                    }
                    else {
                        sig
                    };

                    InputWitness::Standard(sig)
                };

                let sign_with_standalone_private_key = |standalone: &StandaloneInput, destination: &Destination| {
                    produce_uniparty_signature_for_input(
                        is_htlc_input,
                        htlc_secret.clone(),
                        &standalone.private_key,
                        destination.clone(),
                        ptx.tx(),
                        &input_commitments,
                        input_index,
                        self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut()
                    )
                };

                let input_utxo = &ptx.input_utxos()[input_index];

                match witness {
                    Some(w) => match w {
                        InputWitness::NoSignature(_) => Ok((
                            Some(w.clone()),
                            SignatureStatus::FullySigned,
                            SignatureStatus::FullySigned,
                        )),
                        InputWitness::Standard(sig) => match destination {
                            Some(destination) => {
                                if tx_verifier::input_check::signature_only_check::verify_tx_signature(
                                    &self.chain_config,
                                    destination,
                                    &ptx,
                                    &input_commitments,
                                    input_index,
                                    input_utxo.clone()
                                )
                                .is_ok()
                                {
                                    Ok((
                                        Some(w.clone()),
                                        SignatureStatus::FullySigned,
                                        SignatureStatus::FullySigned,
                                    ))
                                } else if let Destination::ClassicMultisig(_) = destination {
                                    let sighash = signature_hash(
                                        sig.sighash_type(),
                                        ptx.tx(),
                                        &input_commitments,
                                        input_index,
                                    )?;

                                    let current_signatures = if is_htlc_input {
                                        let htlc_spend = AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())?;
                                        match htlc_spend {
                                            AuthorizedHashedTimelockContractSpend::Spend(_, _) => {
                                                return Err(SignerError::HtlcRefundExpectedForMultisig);
                                            },
                                            AuthorizedHashedTimelockContractSpend::Refund(raw_sig) => {
                                                AuthorizedClassicalMultisigSpend::from_data(&raw_sig)?
                                            },
                                        }
                                    } else {
                                        AuthorizedClassicalMultisigSpend::from_data(sig.raw_signature())?
                                    };

                                    let previous_status = SignatureStatus::PartialMultisig {
                                        required_signatures: current_signatures
                                            .challenge()
                                            .min_required_signatures(),
                                        num_signatures: current_signatures.signatures().len() as u8,
                                    };

                                    let (current_signatures, new_status) = if let Some(signatures) = new_signatures.get(&input_index)
                                    {
                                        self.update_and_check_multisig(signatures, current_signatures, sighash)?
                                    } else {
                                        (current_signatures, previous_status)
                                    };

                                    let (current_signatures, new_status) =
                                        self.sign_with_standalone_private_keys(
                                            current_signatures,
                                            standalone_inputs.get(&(input_index as u32)).map_or(&[], |x| x.as_slice()),
                                            new_status,
                                            sighash
                                        )?;

                                    let sighash_type = SigHashType::all();
                                    let sig = make_witness(StandardInputSignature::new(
                                        sighash_type,
                                        current_signatures.encode(),
                                    ));

                                    Ok((Some(sig), previous_status, new_status))
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
                    None => match (destination, new_signatures.get(&input_index)) {
                        (Some(destination), Some(sig)) => {
                            let sighash_type = SigHashType::all();
                            let sighash = signature_hash(sighash_type, ptx.tx(), &input_commitments, input_index)?;
                            let (sig, status) = self.make_signature(
                                sig,
                                standalone_inputs.get(&(input_index as u32)).map_or(&[], |x| x.as_slice()),
                                destination,
                                sighash_type,
                                sighash,
                                key_chain,
                                make_witness,
                                sign_with_standalone_private_key,
                            )?;

                            Ok((sig, SignatureStatus::NotSigned, status))
                        }
                        (Some(Destination::AnyoneCanSpend), None) => {
                            Ok((
                                Some(InputWitness::NoSignature(None)),
                                SignatureStatus::NotSigned,
                                SignatureStatus::FullySigned,
                            ))
                        }
                        (Some(destination), None) => {
                            let standalone = match standalone_inputs.get(&(input_index as u32)).map(|x| x.as_slice()) {
                                Some([standalone]) => standalone,
                                Some([]) | None => return Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned)),
                                Some(_) => return Err(LedgerError::MultisigSignatureReturned.into()),
                            };

                            let sig = produce_uniparty_signature_for_input(
                                is_htlc_input,
                                htlc_secret.clone(),
                                &standalone.private_key,
                                destination.clone(),
                                ptx.tx(),
                                &input_commitments,
                                input_index,
                                self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut()
                            )?;


                            Ok((Some(sig), SignatureStatus::NotSigned, SignatureStatus::FullySigned))
                        }
                        (None, _) => {
                            Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned))
                        }
                    },
                }
            }),
            |iter| iter.multiunzip()
        )?;

        Ok((ptx.with_witnesses(witnesses)?, prev_statuses, new_statuses))
    }

    async fn sign_challenge(
        &mut self,
        message: &[u8],
        destination: &Destination,
        key_chain: &(impl AccountKeyChains + Sync),
        mut db_tx: impl WalletStorageReadUnlocked + Send,
    ) -> SignerResult<ArbitraryMessageSignature> {
        let data = match key_chain.find_public_key(destination) {
            Some(FoundPubKey::Hierarchy(xpub)) => {
                let address_n = LedgerBip32Path(
                    xpub.get_derivation_path()
                        .as_slice()
                        .iter()
                        .map(|c| c.into_encoded_index())
                        .collect(),
                );

                let addr_type = match destination {
                    Destination::PublicKey(_) => AddrType::PublicKey,
                    Destination::PublicKeyHash(_) => AddrType::PublicKeyHash,
                    Destination::AnyoneCanSpend => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend,
                        ))
                    }
                    Destination::ClassicMultisig(_) => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
                        ))
                    }
                    Destination::ScriptHash(_) => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::Unsupported,
                        ))
                    }
                };

                let coin_type = to_ledger_chain_type(&self.chain_config);
                let message = message.to_vec();
                let sig = self
                    .perform_ledger_operation(
                        async move |client| {
                            sign_challenge(client, coin_type, address_n, addr_type, &message).await
                        },
                        &mut db_tx,
                        key_chain,
                    )
                    .await?;

                let signature = Signature::from_raw_data(&sig, SignatureKind::Secp256k1Schnorr)
                    .map_err(LedgerError::SignatureError)?;

                match &destination {
                        Destination::PublicKey(_) => Ok(AuthorizedPublicKeySpend::new(signature).encode()),
                        Destination::PublicKeyHash(_) => {
                            Ok(AuthorizedPublicKeyHashSpend::new(xpub.into_public_key(), signature)
                                .encode())
                        }
                        Destination::AnyoneCanSpend => {
                            Err(SignerError::SigningError(
                                DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend,
                            ))
                        }
                        Destination::ClassicMultisig(_) => {
                            Err(SignerError::SigningError(
                                DestinationSigError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
                            ))
                        }
                        Destination::ScriptHash(_) => {
                            Err(SignerError::SigningError(
                                DestinationSigError::Unsupported,
                            ))
                        }
                    }?
            }
            Some(FoundPubKey::Standalone(acc_public_key)) => {
                let standalone_pk = db_tx
                    .get_account_standalone_private_key(&acc_public_key)?
                    .ok_or(SignerError::DestinationNotFromThisWallet)?;

                let sig = ArbitraryMessageSignature::produce_uniparty_signature(
                    &standalone_pk,
                    destination,
                    message,
                    self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut(),
                )?;
                return Ok(sig);
            }
            None => return Err(SignerError::DestinationNotFromThisWallet),
        };

        let sig = ArbitraryMessageSignature::from_data(data);
        Ok(sig)
    }

    async fn sign_transaction_intent(
        &mut self,
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent: &str,
        key_chain: &(impl AccountKeyChains + Sync),
        mut db_tx: impl WalletStorageReadUnlocked + Send,
    ) -> SignerResult<SignedTransactionIntent> {
        let tx_id = transaction.get_id();
        let message_to_sign = SignedTransactionIntent::get_message_to_sign(intent, &tx_id);

        let mut signatures = Vec::with_capacity(input_destinations.len());
        for dest in input_destinations {
            let dest = SignedTransactionIntent::normalize_destination(dest);
            let sig = self
                .sign_challenge(message_to_sign.as_bytes(), &dest, key_chain, &mut db_tx)
                .await?;

            signatures.push(sig.into_raw());
        }

        SignedTransactionIntent::from_components(
            message_to_sign,
            signatures,
            input_destinations,
            &self.chain_config,
        )
        .map_err(Into::into)
    }
}

fn to_ledger_input_msgs(
    ptx: &PartiallySignedTransaction,
    key_chain: &impl AccountKeyChains,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<TxInputReq>, StandaloneInputs)> {
    let res: (Vec<_>, BTreeMap<_, _>) = itertools::process_results(
        ptx.tx()
            .inputs()
            .iter()
            .zip(ptx.destinations())
            .zip(ptx.input_utxos())
            .enumerate()
            .map(|(idx, ((inp, dest), utxo))| -> SignerResult<_> {
                let (address_paths, standalone_inputs) =
                    dest.as_ref().map_or(Ok((vec![], vec![])), |dest| {
                        destination_to_address_paths(key_chain, dest, db_tx)
                    })?;

                let input = TxInputReq {
                    inp: to_ledger_tx_input_with_additional_info(inp, utxo, ptx.additional_info())?,
                    addresses: address_paths,
                };

                Ok((input, (idx as u32, standalone_inputs)))
            }),
        |iter| iter.unzip(),
    )?;

    Ok(res)
}

fn to_ledger_tx_input_with_additional_info(
    inp: &TxInput,
    utxo: &Option<TxOutput>,
    additional_info: &PtxAdditionalInfo,
) -> SignerResult<TxInputWithAdditionalInfo> {
    let inp = match inp {
        TxInput::Utxo(outpoint) => {
            let utxo = utxo.as_ref().ok_or(SignerError::MissingUtxo)?;
            let info = match utxo {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    let pool_info = additional_info
                        .get_pool_info(pool_id)
                        .ok_or(SignerError::MissingTxExtraInfo)?;
                    AdditionalUtxoInfo::PoolData {
                        utxo: utxo.clone().try_convert_into()?,
                        staker_balance: pool_info.staker_balance.try_convert_into()?,
                    }
                }
                _ => AdditionalUtxoInfo::Utxo(utxo.clone().try_convert_into()?),
            };
            TxInputWithAdditionalInfo::Utxo(outpoint.clone().try_convert_into()?, info)
        }
        TxInput::Account(acc) => {
            TxInputWithAdditionalInfo::Account(acc.clone().try_convert_into()?)
        }
        TxInput::AccountCommand(nonce, cmd) => TxInputWithAdditionalInfo::AccountCommand(
            (*nonce).try_convert_into()?,
            cmd.clone().try_convert_into()?,
        ),
        TxInput::OrderAccountCommand(cmd) => {
            let info = additional_info
                .get_order_info(cmd.order_id())
                .ok_or(SignerError::MissingTxExtraInfo)?;

            TxInputWithAdditionalInfo::OrderAccountCommand(
                cmd.clone().try_convert_into()?,
                AdditionalOrderInfo {
                    initially_asked: info.initially_asked.clone().try_convert_into()?,
                    initially_given: info.initially_given.clone().try_convert_into()?,
                    ask_balance: info.ask_balance.try_convert_into()?,
                    give_balance: info.give_balance.try_convert_into()?,
                },
            )
        }
    };
    Ok(inp)
}

/// Find the derivation paths to the key in the destination, or multiple in the case of a multisig
fn destination_to_address_paths(
    key_chain: &impl AccountKeyChains,
    dest: &Destination,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<LedgerInputAddressPath>, Vec<StandaloneInput>)> {
    destination_to_address_paths_impl(key_chain, dest, None, db_tx)
}

fn destination_to_address_paths_impl(
    key_chain: &impl AccountKeyChains,
    dest: &Destination,
    multisig_idx: Option<u32>,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<LedgerInputAddressPath>, Vec<StandaloneInput>)> {
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            Ok((
                vec![LedgerInputAddressPath {
                    path: LedgerBip32Path(address_n),
                    multisig_idx,
                }],
                vec![],
            ))
        }
        Some(FoundPubKey::Standalone(acc_public_key)) => {
            let standalone_input =
                db_tx.get_account_standalone_private_key(&acc_public_key)?.map(|private_key| {
                    StandaloneInput {
                        multisig_idx,
                        private_key,
                    }
                });
            Ok((vec![], standalone_input.into_iter().collect()))
        }
        None if multisig_idx.is_none() => {
            if let Some(challenge) = key_chain.find_multisig_challenge(dest) {
                let (x, y): (Vec<_>, Vec<_>) = itertools::process_results(
                    challenge.public_keys().iter().enumerate().map(|(idx, pk)| {
                        destination_to_address_paths_impl(
                            key_chain,
                            &Destination::PublicKey(pk.clone()),
                            Some(idx as u32),
                            db_tx,
                        )
                    }),
                    |iter| iter.unzip(),
                )?;

                Ok((
                    x.into_iter().flatten().collect(),
                    y.into_iter().flatten().collect(),
                ))
            } else {
                Ok((vec![], vec![]))
            }
        }
        None => Ok((vec![], vec![])),
    }
}

fn to_ledger_input_commitments_reqs(
    ptx: &PartiallySignedTransaction,
) -> SignerResult<Vec<LSighashInputCommitment>> {
    ptx.input_utxos()
        .iter()
        .zip(ptx.tx().inputs())
        .map(|(utxo, inp)| {
            let additional_info = match inp {
                TxInput::Utxo(_) => {
                    let utxo = utxo.as_ref().ok_or(SignerError::MissingUtxo)?;
                    match utxo {
                        TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let pool_info = ptx
                                .additional_info()
                                .get_pool_info(pool_id)
                                .ok_or(SignerError::MissingTxExtraInfo)?;
                            LSighashInputCommitment::ProduceBlockFromStakeUtxo {
                                utxo: utxo.clone().try_convert_into()?,
                                staker_balance: pool_info.staker_balance.try_convert_into()?,
                            }
                        }
                        _ => LSighashInputCommitment::Utxo(utxo.clone().try_convert_into()?),
                    }
                }
                TxInput::Account(_) => LSighashInputCommitment::None,
                TxInput::AccountCommand(_, cmd) => match cmd {
                    AccountCommand::MintTokens(_, _)
                    | AccountCommand::UnmintTokens(_)
                    | AccountCommand::LockTokenSupply(_)
                    | AccountCommand::FreezeToken(_, _)
                    | AccountCommand::UnfreezeToken(_)
                    | AccountCommand::ChangeTokenAuthority(_, _)
                    | AccountCommand::ChangeTokenMetadataUri(_, _) => LSighashInputCommitment::None,
                    AccountCommand::FillOrder(order_id, _, _) => {
                        let order_info = ptx
                            .additional_info()
                            .get_order_info(order_id)
                            .ok_or(SignerError::MissingTxExtraInfo)?;
                        LSighashInputCommitment::FillOrderAccountCommand {
                            initially_asked: order_info
                                .initially_asked
                                .clone()
                                .try_convert_into()?,
                            initially_given: order_info
                                .initially_given
                                .clone()
                                .try_convert_into()?,
                        }
                    }
                    AccountCommand::ConcludeOrder(order_id) => {
                        let order_info = ptx
                            .additional_info()
                            .get_order_info(order_id)
                            .ok_or(SignerError::MissingTxExtraInfo)?;
                        LSighashInputCommitment::ConcludeOrderAccountCommand {
                            initially_asked: order_info
                                .initially_asked
                                .clone()
                                .try_convert_into()?,
                            initially_given: order_info
                                .initially_given
                                .clone()
                                .try_convert_into()?,
                            ask_balance: order_info.ask_balance.try_convert_into()?,
                            give_balance: order_info.give_balance.try_convert_into()?,
                        }
                    }
                },
                | TxInput::OrderAccountCommand(cmd) => match cmd {
                    OrderAccountCommand::FillOrder(order_id, _) => {
                        let order_info = ptx
                            .additional_info()
                            .get_order_info(order_id)
                            .ok_or(SignerError::MissingTxExtraInfo)?;
                        LSighashInputCommitment::FillOrderAccountCommand {
                            initially_asked: order_info
                                .initially_asked
                                .clone()
                                .try_convert_into()?,
                            initially_given: order_info
                                .initially_given
                                .clone()
                                .try_convert_into()?,
                        }
                    }
                    OrderAccountCommand::ConcludeOrder(order_id) => {
                        let order_info = ptx
                            .additional_info()
                            .get_order_info(order_id)
                            .ok_or(SignerError::MissingTxExtraInfo)?;
                        LSighashInputCommitment::ConcludeOrderAccountCommand {
                            initially_asked: order_info
                                .initially_asked
                                .clone()
                                .try_convert_into()?,
                            initially_given: order_info
                                .initially_given
                                .clone()
                                .try_convert_into()?,
                            ask_balance: order_info.ask_balance.try_convert_into()?,
                            give_balance: order_info.give_balance.try_convert_into()?,
                        }
                    }
                    OrderAccountCommand::FreezeOrder(_) => LSighashInputCommitment::None,
                },
            };
            Ok(additional_info)
        })
        .collect()
}

fn to_ledger_chain_type(chain_config: &ChainConfig) -> CoinType {
    match chain_config.chain_type() {
        ChainType::Mainnet => CoinType::Mainnet,
        ChainType::Testnet => CoinType::Testnet,
        ChainType::Signet => CoinType::Regtest,
        ChainType::Regtest => CoinType::Signet,
    }
}

async fn find_ledger_device() -> SignerResult<(LedgerHandle, LedgerFullInfo)> {
    let mut provider = LedgerProvider::init().await;
    let mut devices = provider
        .list(Filters::Any)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;

    let device = devices.pop().ok_or(LedgerError::NoDeviceFound)?;
    let model = to_ledger_model(&device.model);

    let mut handle = provider
        .connect(device)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;

    let app_version = check_current_app(&mut handle).await?;

    Ok((handle, LedgerFullInfo { app_version, model }))
}

/// Check that the public keys in the provided key chain are the same as the ones from the
/// connected hardware wallet
async fn check_public_keys_against_key_chain<L: Exchange, T: WalletStorageReadLocked>(
    db_tx: &mut T,
    client: &mut L,
    key_chain: &impl AccountKeyChains,
    chain_config: &ChainConfig,
) -> SignerResult<()> {
    let expected_pk =
        fetch_extended_pub_key(client, chain_config, key_chain.account_index()).await?;

    if key_chain.account_public_key() == &expected_pk {
        return Ok(());
    }

    if let Ok(Some(_data)) = db_tx.get_hardware_wallet_data() {
        // Data is empty there is nothing to compare
        return Err(LedgerError::HardwareWalletDifferentMnemonicOrPassphrase.into());
    }

    Err(LedgerError::WalletFileIsSoftwareWallet.into())
}

/// Check that the public keys in the DB are the same as the ones from the connected hardware
/// wallet
async fn check_public_keys_against_db<T: WalletStorageReadLocked + Send>(
    db_tx: &mut T,
    client: &mut LedgerHandle,
    chain_config: Arc<ChainConfig>,
) -> SignerResult<()> {
    let (id, first_acc) = db_tx
        .get_accounts_info()?
        .iter()
        .find_map(|(id, info)| {
            (info.account_index() == DEFAULT_ACCOUNT_INDEX).then_some((id.clone(), info.clone()))
        })
        .ok_or(SignerError::WalletNotInitialized)?;

    let loaded_acc = AccountKeyChainImplHardware::load_from_database(
        chain_config.clone(),
        db_tx,
        &id,
        &first_acc,
    )?;

    check_public_keys_against_key_chain(db_tx, client, &loaded_acc, &chain_config).await
}

async fn fetch_extended_pub_key<L: Exchange>(
    client: &mut L,
    chain_config: &ChainConfig,
    account_index: U31,
) -> SignerResult<ExtendedPublicKey> {
    let derivation_path = make_account_path(chain_config, account_index);
    let coin_type = to_ledger_chain_type(chain_config);

    get_extended_public_key(client, coin_type, derivation_path).await
}

fn single_signature(
    signatures: &[LedgerSignature],
) -> Result<Option<&LedgerSignature>, LedgerError> {
    match signatures {
        [] => Ok(None),
        [single] => {
            ensure!(
                single.multisig_idx.is_none(),
                LedgerError::MultisigSignatureReturned
            );
            Ok(Some(single))
        }
        _ => Err(LedgerError::MultipleSignaturesReturned),
    }
}

#[derive(Clone, derive_more::Debug)]
pub struct LedgerSignerProvider {
    #[debug(skip)]
    client: Arc<Mutex<LedgerHandle>>,
    info: LedgerFullInfo,
}

#[async_trait]
impl LedgerFinder for LedgerSignerProvider {
    type Ledger = LedgerHandle;

    async fn find_ledger_device_from_db<T: WalletStorageReadLocked + Send>(
        &self,
        db_tx: &mut T,
        chain_config: Arc<ChainConfig>,
    ) -> SignerResult<(Self::Ledger, LedgerData)> {
        let (mut client, info) = find_ledger_device().await?;

        check_public_keys_against_db(db_tx, &mut client, chain_config).await?;

        Ok((client, info.into()))
    }
}

impl LedgerSignerProvider {
    pub async fn new() -> SignerResult<Self> {
        let (client, info) = find_ledger_device().await?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            info,
        })
    }

    pub async fn load_from_database<T: WalletStorageReadLocked + Send>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut T,
    ) -> WalletResult<Self> {
        let (mut client, info) = find_ledger_device().await?;

        check_public_keys_against_db(db_tx, &mut client, chain_config).await?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            info,
        })
    }

    async fn fetch_extended_pub_key(
        &self,
        chain_config: &Arc<ChainConfig>,
        account_index: U31,
    ) -> SignerResult<ExtendedPublicKey> {
        fetch_extended_pub_key(&mut *self.client.lock().await, chain_config, account_index).await
    }
}

#[async_trait]
impl SignerProvider for LedgerSignerProvider {
    type S = LedgerSigner<LedgerHandle, LedgerSignerProvider>;
    type K = AccountKeyChainImplHardware;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, _account_index: U31) -> Self::S {
        LedgerSigner::new(chain_config, self.client.clone(), self.clone())
    }

    async fn make_new_account<T: WalletStorageWriteUnlocked + Send>(
        &mut self,
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        name: Option<String>,
        db_tx: &mut T,
    ) -> WalletResult<Account<Self::K>> {
        let account_pubkey = self.fetch_extended_pub_key(&chain_config, account_index).await?;

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

    fn get_hardware_wallet_info(&self) -> Option<HardwareWalletFullInfo> {
        Some(HardwareWalletFullInfo::Ledger(self.info.clone()))
    }
}

fn to_ledger_model(model: &Model) -> LedgerModel {
    match model {
        Model::NanoS => LedgerModel::NanoS,
        Model::NanoSPlus => LedgerModel::NanoSPlus,
        Model::NanoX => LedgerModel::NanoX,
        Model::Stax => LedgerModel::Stax,
        Model::Unknown(m) => LedgerModel::Unknown(*m),
    }
}

#[cfg(feature = "enable-ledger-device-tests")]
#[cfg(test)]
mod tests;
