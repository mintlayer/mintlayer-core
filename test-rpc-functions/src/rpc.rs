// Copyright (c) 2022 RBB S.r.l
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

//! Block production subsystem RPC handler

use std::str::FromStr;

use chainstate::rpc::RpcUtxoOutpoint;
use chainstate_types::vrf_tools::{construct_transcript, verify_vrf_and_get_vrf_output};
use common::{
    address::{dehexify, Address},
    chain::{
        block::timestamp::BlockTimestamp,
        config::{
            regtest::{genesis_values, GenesisStakingSettings},
            EpochIndex,
        },
        output_value::OutputValue,
        signature::inputsig::{
            arbitrary_message,
            authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
            InputWitness,
        },
        stakelock::StakePoolData,
        tokens::TokenId,
        Destination, OutPointSourceId, PoolId, SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable, H256},
};
use crypto::key::Signature;
use serialization::{
    hex::{HexDecode, HexEncode},
    hex_encoded::HexEncoded,
    Encode as _,
};
use wallet_types::partially_signed_transaction::PartiallySignedTransaction;

use crate::{RpcTestFunctionsError, RpcTestFunctionsHandle};

#[rpc::describe]
#[rpc::rpc(server, namespace = "test_functions")]
trait RpcTestFunctionsRpc {
    #[method(name = "genesis_pool_id")]
    async fn genesis_pool_id(&self) -> rpc::RpcResult<Option<String>>;

    #[method(name = "genesis_private_key")]
    async fn genesis_private_key(&self) -> rpc::RpcResult<Option<String>>;

    #[method(name = "genesis_public_key")]
    async fn genesis_public_key(&self) -> rpc::RpcResult<Option<String>>;

    #[method(name = "genesis_vrf_private_key")]
    async fn genesis_vrf_private_key(&self) -> rpc::RpcResult<Option<String>>;

    #[method(name = "genesis_vrf_public_key")]
    async fn genesis_vrf_public_key(&self) -> rpc::RpcResult<Option<String>>;

    #[method(name = "new_private_key")]
    async fn new_private_key(&self) -> rpc::RpcResult<String>;

    #[method(name = "public_key_from_private_key")]
    async fn public_key_from_private_key(&self, private_key_hex: String) -> rpc::RpcResult<String>;

    #[method(name = "public_key_to_public_key_address")]
    async fn public_key_to_public_key_address(
        &self,
        public_key_hex: String,
    ) -> rpc::RpcResult<String>;

    #[method(name = "public_key_to_public_key_hash_address")]
    async fn public_key_to_public_key_hash_address(
        &self,
        public_key_hex: String,
    ) -> rpc::RpcResult<String>;

    /// Return the actual message that is signed when producing an arbitrary message signature.
    ///
    /// Note that the result is returned as a hex-encoded `Vec<u8>`, which is suitable for passing
    /// to `sign_message_with_private_key` and `verify_message_with_public_key`.
    #[method(name = "produce_message_challenge_for_arbitrary_message_signature")]
    async fn produce_message_challenge_for_arbitrary_message_signature(
        &self,
        message_hex: String,
    ) -> rpc::RpcResult<String>;

    #[method(name = "sign_message_with_private_key")]
    async fn sign_message_with_private_key(
        &self,
        private_key_hex: String,
        message_hex: String,
    ) -> rpc::RpcResult<String>;

    #[method(name = "verify_message_with_public_key")]
    async fn verify_message_with_public_key(
        &self,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    ) -> rpc::RpcResult<bool>;

    #[method(name = "new_vrf_private_key")]
    async fn new_vrf_private_key(&self) -> rpc::RpcResult<String>;

    #[method(name = "vrf_public_key_from_private_key")]
    async fn vrf_public_key_from_private_key(
        &self,
        private_key_hex: String,
    ) -> rpc::RpcResult<String>;

    #[method(name = "sign_message_with_vrf_private_key")]
    async fn sign_message_with_vrf_private_key(
        &self,
        private_key_hex: String,
        epoch_index: EpochIndex,
        random_seed: String,
        block_timestamp: u64,
    ) -> rpc::RpcResult<String>;

    #[method(name = "verify_then_get_vrf_output")]
    async fn verify_then_get_vrf_output(
        &self,
        epoch_index: EpochIndex,
        random_seed: String,
        vrf_data: String,
        vrf_public_key: String,
        block_timestamp: BlockTimestamp,
    ) -> rpc::RpcResult<String>;

    #[method(name = "generate_transactions")]
    async fn generate_transactions(
        &self,
        input_tx_id: Id<Transaction>,
        input_idx: u32,
        num_transactions: u32,
        amount_to_spend: u64,
        fee_per_tx: u64,
    ) -> rpc::RpcResult<Vec<HexEncoded<SignedTransaction>>>;

    #[method(name = "address_to_destination")]
    async fn address_to_destination(
        &self,
        address: String,
    ) -> rpc::RpcResult<HexEncoded<Destination>>;

    #[method(name = "dehexify_all_addresses")]
    async fn dehexify_all_addresses(&self, input: String) -> rpc::RpcResult<String>;

    #[method(name = "partially_signed_tx_to_signed_tx")]
    async fn partially_signed_tx_to_signed_tx(
        &self,
        input: HexEncoded<PartiallySignedTransaction>,
    ) -> rpc::RpcResult<Option<HexEncoded<SignedTransaction>>>;

    #[method(name = "reveal_token_id")]
    async fn reveal_token_id(&self, token_id: String) -> rpc::RpcResult<HexEncoded<TokenId>>;

    #[method(name = "extract_htlc_secret")]
    async fn extract_htlc_secret(
        &self,
        signed_tx_hex: String,
        htlc_outpoint: RpcUtxoOutpoint,
    ) -> rpc::RpcResult<Option<String>>;
}

#[async_trait::async_trait]
impl RpcTestFunctionsRpcServer for super::RpcTestFunctionsHandle {
    async fn genesis_pool_id(&self) -> rpc::RpcResult<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_pool_id.hex_encode()),
        )
    }

    async fn genesis_private_key(&self) -> rpc::RpcResult<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, genesis_stake_private_key, _, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_stake_private_key.hex_encode()),
        )
    }

    async fn genesis_public_key(&self) -> rpc::RpcResult<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, genesis_stake_public_key, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_stake_public_key.hex_encode()),
        )
    }

    async fn genesis_vrf_private_key(&self) -> rpc::RpcResult<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, genesis_vrf_private_key, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_vrf_private_key.hex_encode()),
        )
    }

    async fn genesis_vrf_public_key(&self) -> rpc::RpcResult<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, _, genesis_vrf_public_key) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_vrf_public_key.hex_encode()),
        )
    }

    async fn new_private_key(&self) -> rpc::RpcResult<String> {
        let keys =
            crypto::key::PrivateKey::new_from_entropy(crypto::key::KeyKind::Secp256k1Schnorr);

        Ok(keys.0.hex_encode())
    }

    async fn public_key_from_private_key(&self, private_key_hex: String) -> rpc::RpcResult<String> {
        let private_key =
            rpc::handle_result(crypto::key::PrivateKey::hex_decode_all(private_key_hex))?;

        let public_key = crypto::key::PublicKey::from_private_key(&private_key);

        Ok(public_key.hex_encode())
    }

    async fn public_key_to_public_key_address(
        &self,
        public_key_hex: String,
    ) -> rpc::RpcResult<String> {
        let public_key =
            rpc::handle_result(crypto::key::PublicKey::hex_decode_all(public_key_hex))?;
        let destination = Destination::PublicKey(public_key);

        let address = self
            .call(|this| {
                let chain_config = this.get_chain_config().expect("chain config must be present");
                Address::new(&chain_config, destination)
                    .expect("destination must be encodable")
                    .into_string()
            })
            .await
            .expect("Subsystem call ok");
        Ok(address)
    }

    async fn public_key_to_public_key_hash_address(
        &self,
        public_key_hex: String,
    ) -> rpc::RpcResult<String> {
        let public_key: crypto::key::PublicKey =
            rpc::handle_result(crypto::key::PublicKey::hex_decode_all(public_key_hex))?;
        let destination = Destination::PublicKeyHash((&public_key).into());

        let address = self
            .call(|this| {
                let chain_config = this.get_chain_config().expect("chain config must be present");
                Address::new(&chain_config, destination)
                    .expect("destination must be encodable")
                    .into_string()
            })
            .await
            .expect("Subsystem call ok");
        Ok(address)
    }

    async fn produce_message_challenge_for_arbitrary_message_signature(
        &self,
        message_hex: String,
    ) -> rpc::RpcResult<String> {
        let message: Vec<u8> = rpc::handle_result(Vec::<u8>::hex_decode_all(message_hex))?;
        let challenge = arbitrary_message::produce_message_challenge(&message);
        let resulting_message = challenge.encode();
        Ok(resulting_message.hex_encode())
    }

    async fn sign_message_with_private_key(
        &self,
        private_key_hex: String,
        message_hex: String,
    ) -> rpc::RpcResult<String> {
        let private_key: crypto::key::PrivateKey =
            rpc::handle_result(crypto::key::PrivateKey::hex_decode_all(private_key_hex))?;

        let message: Vec<u8> = rpc::handle_result(Vec::<u8>::hex_decode_all(message_hex))?;

        let signature = private_key
            .sign_message(&message, randomness::make_true_rng())
            .map_err(RpcTestFunctionsError::from);
        let signature: Signature = rpc::handle_result(signature)?;

        Ok(signature.hex_encode())
    }

    async fn verify_message_with_public_key(
        &self,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    ) -> rpc::RpcResult<bool> {
        let public_key: crypto::key::PublicKey =
            rpc::handle_result(crypto::key::PublicKey::hex_decode_all(public_key_hex))?;

        let message: Vec<u8> = rpc::handle_result(Vec::<u8>::hex_decode_all(message_hex))?;
        let signature = rpc::handle_result(Signature::hex_decode_all(signature_hex))?;

        let verify_result = public_key.verify_message(&signature, &message);

        Ok(verify_result)
    }

    async fn new_vrf_private_key(&self) -> rpc::RpcResult<String> {
        let keys =
            crypto::vrf::VRFPrivateKey::new_from_entropy(crypto::vrf::VRFKeyKind::Schnorrkel);

        Ok(keys.0.hex_encode())
    }

    async fn vrf_public_key_from_private_key(
        &self,
        private_key_hex: String,
    ) -> rpc::RpcResult<String> {
        let private_key =
            rpc::handle_result(crypto::vrf::VRFPrivateKey::hex_decode_all(private_key_hex))?;

        let public_key = crypto::vrf::VRFPublicKey::from_private_key(&private_key);

        Ok(public_key.hex_encode())
    }

    async fn sign_message_with_vrf_private_key(
        &self,
        private_key_hex: String,
        epoch_index: EpochIndex,
        random_seed: String,
        block_timestamp: u64,
    ) -> rpc::RpcResult<String> {
        let random_seed: H256 = rpc::handle_result(H256::hex_decode_all(random_seed))?;

        let transcript = construct_transcript(
            epoch_index,
            &random_seed,
            BlockTimestamp::from_int_seconds(block_timestamp),
        );
        let private_key: crypto::vrf::VRFPrivateKey =
            rpc::handle_result(crypto::vrf::VRFPrivateKey::hex_decode_all(private_key_hex))?;

        let signature = private_key.produce_vrf_data(transcript);

        Ok(signature.hex_encode())
    }

    async fn verify_then_get_vrf_output(
        &self,
        epoch_index: EpochIndex,
        random_seed: String,
        vrf_data: String,
        vrf_public_key: String,
        block_timestamp: BlockTimestamp,
    ) -> rpc::RpcResult<String> {
        let vrf_data = rpc::handle_result(crypto::vrf::VRFReturn::hex_decode_all(vrf_data))?;
        let vrf_public_key =
            rpc::handle_result(crypto::vrf::VRFPublicKey::hex_decode_all(vrf_public_key))?;
        let random_seed = rpc::handle_result(H256::hex_decode_all(random_seed))?;

        let vrf_output = verify_vrf_and_get_vrf_output(
            epoch_index,
            &random_seed,
            &vrf_data,
            &vrf_public_key,
            block_timestamp,
        )
        .map_err(RpcTestFunctionsError::from);

        let vrf_output: H256 = rpc::handle_result(vrf_output)?;

        Ok(vrf_output.hex_encode())
    }

    async fn generate_transactions(
        &self,
        mut input_tx_id: Id<Transaction>,
        mut input_idx: u32,
        num_transactions: u32,
        amount_to_spend: u64,
        fee_per_tx: u64,
    ) -> rpc::RpcResult<Vec<HexEncoded<SignedTransaction>>> {
        let coin_decimals = self
            .call(|this| this.get_chain_config().map(|chain| chain.coin_decimals()))
            .await
            .expect("Subsystem call ok")
            .expect("chain config is present");
        let coin_decimal_factor = 10u128.pow(coin_decimals as u32);
        let mut amount_to_spend = (amount_to_spend as u128) * coin_decimal_factor;
        let fee_per_tx = (fee_per_tx as u128) * coin_decimal_factor;
        let mut transactions = Vec::with_capacity(num_transactions as usize);
        for _ in 0..num_transactions {
            let inputs =
                vec![TxInput::from_utxo(OutPointSourceId::Transaction(input_tx_id), input_idx)];
            let mut outputs = vec![TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(amount_to_spend)),
                Destination::AnyoneCanSpend,
            )];
            outputs.extend((0..9999).map(|_| {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(1)),
                    Destination::AnyoneCanSpend,
                )
            }));

            let transaction = SignedTransaction::new(
                Transaction::new(0, inputs, outputs).expect("should not fail"),
                vec![InputWitness::NoSignature(None)],
            )
            .expect("num signatures ok");

            input_tx_id = transaction.transaction().get_id();
            input_idx = 0;
            amount_to_spend -= 10000;
            amount_to_spend -= fee_per_tx;

            transactions.push(HexEncoded::new(transaction));
        }

        Ok(transactions)
    }

    async fn address_to_destination(
        &self,
        address: String,
    ) -> rpc::RpcResult<HexEncoded<Destination>> {
        let destination = self
            .call(move |this| {
                this.get_chain_config().map(|chain| {
                    Address::<Destination>::from_string(&chain, &address).map(|a| a.into_object())
                })
            })
            .await
            .expect("Subsystem call ok")
            .expect("chain config is present")
            .map(HexEncoded::new);

        rpc::handle_result(destination)
    }

    async fn dehexify_all_addresses(&self, input: String) -> rpc::RpcResult<String> {
        let output = self
            .call(|this| {
                if let Some(chain_config) = this.get_chain_config() {
                    dehexify::dehexify_all_addresses(&chain_config, &input)
                } else {
                    input
                }
            })
            .await
            .expect("Subsystem call ok");

        Ok(output)
    }

    async fn partially_signed_tx_to_signed_tx(
        &self,
        tx: HexEncoded<PartiallySignedTransaction>,
    ) -> rpc::RpcResult<Option<HexEncoded<SignedTransaction>>> {
        Ok(tx.take().into_signed_tx().ok().map(HexEncoded::new))
    }

    async fn reveal_token_id(&self, token_id: String) -> rpc::RpcResult<HexEncoded<TokenId>> {
        let result = self
            .call(move |this| {
                this.get_chain_config().map(|chain| {
                    Address::<TokenId>::from_string(&chain, &token_id).map(|a| a.into_object())
                })
            })
            .await
            .expect("Subsystem call ok")
            .expect("chain config is present")
            .map(HexEncoded::new);

        rpc::handle_result(result)
    }

    async fn extract_htlc_secret(
        &self,
        signed_tx_hex: String,
        htlc_outpoint: RpcUtxoOutpoint,
    ) -> rpc::RpcResult<Option<String>> {
        let tx = HexEncoded::<SignedTransaction>::from_str(&signed_tx_hex).expect("ok").take();

        let htlc_outpoint = htlc_outpoint.into_outpoint();
        let htlc_position = tx.transaction().inputs().iter().position(|input| match input {
            TxInput::Utxo(outpoint) => *outpoint == htlc_outpoint,
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => false,
        });

        match htlc_position {
            Some(i) => match tx.signatures().get(i).expect("ok") {
                InputWitness::NoSignature(_) => Ok(None),
                InputWitness::Standard(sig) => {
                    let htlc_spend_result =
                        AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())
                            .map_err(RpcTestFunctionsError::from);
                    let htlc_spend: AuthorizedHashedTimelockContractSpend =
                        rpc::handle_result(htlc_spend_result)?;
                    match htlc_spend {
                        AuthorizedHashedTimelockContractSpend::Secret(secret, _) => {
                            Ok(Some(secret.hex_encode()))
                        }
                        AuthorizedHashedTimelockContractSpend::Multisig(_) => Ok(None),
                    }
                }
            },
            None => Ok(None),
        }
    }
}

async fn assert_genesis_values(
    handle: &RpcTestFunctionsHandle,
    genesis_pool_id: PoolId,
    genesis_stake_pool_data: Box<StakePoolData>,
) -> bool {
    let expected_genesis_pool_txoutput =
        TxOutput::CreateStakePool(genesis_pool_id, genesis_stake_pool_data);

    let current_create_genesis_pool_txoutput = handle
        .call(|this| {
            this.get_chain_config()
                .and_then(|chain| chain.genesis_block().utxos().get(1).map(|u| u.hex_encode()))
        })
        .await
        .expect("Subsystem call ok");

    match current_create_genesis_pool_txoutput {
        None => false,
        Some(txoutput) => {
            assert!(txoutput == expected_genesis_pool_txoutput.hex_encode());
            true
        }
    }
}
