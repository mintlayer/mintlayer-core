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

use chainstate_types::vrf_tools::{construct_transcript, verify_vrf_and_get_vrf_output};
use common::{
    chain::config::regtest::genesis_values,
    chain::{
        block::timestamp::BlockTimestamp,
        config::{regtest::GenesisStakingSettings, EpochIndex},
        stakelock::StakePoolData,
        PoolId, TxOutput,
    },
    primitives::H256,
};
use crypto::key::Signature;
use serialization::{hex::HexDecode, hex::HexEncode};

use crate::{RpcTestFunctionsError, RpcTestFunctionsHandle};

#[rpc::rpc(server, namespace = "test_functions")]
trait RpcTestFunctionsRpc {
    #[method(name = "genesis_pool_id")]
    async fn genesis_pool_id(&self) -> rpc::Result<Option<String>>;

    #[method(name = "genesis_private_key")]
    async fn genesis_private_key(&self) -> rpc::Result<Option<String>>;

    #[method(name = "genesis_public_key")]
    async fn genesis_public_key(&self) -> rpc::Result<Option<String>>;

    #[method(name = "genesis_vrf_private_key")]
    async fn genesis_vrf_private_key(&self) -> rpc::Result<Option<String>>;

    #[method(name = "genesis_vrf_public_key")]
    async fn genesis_vrf_public_key(&self) -> rpc::Result<Option<String>>;

    #[method(name = "new_private_key")]
    async fn new_private_key(&self) -> rpc::Result<String>;

    #[method(name = "public_key_from_private_key")]
    async fn public_key_from_private_key(&self, private_key_hex: String) -> rpc::Result<String>;

    #[method(name = "sign_message_with_private_key")]
    async fn sign_message_with_private_key(
        &self,
        private_key_hex: String,
        message_hex: String,
    ) -> rpc::Result<String>;

    #[method(name = "verify_message_with_public_key")]
    async fn verify_message_with_public_key(
        &self,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    ) -> rpc::Result<bool>;

    #[method(name = "new_vrf_private_key")]
    async fn new_vrf_private_key(&self) -> rpc::Result<String>;

    #[method(name = "vrf_public_key_from_private_key")]
    async fn vrf_public_key_from_private_key(&self, private_key_hex: String)
        -> rpc::Result<String>;

    #[method(name = "sign_message_with_vrf_private_key")]
    async fn sign_message_with_vrf_private_key(
        &self,
        private_key_hex: String,
        epoch_index: EpochIndex,
        random_seed: String,
        block_timestamp: u64,
    ) -> rpc::Result<String>;

    #[method(name = "verify_then_get_vrf_output")]
    async fn verify_then_get_vrf_output(
        &self,
        epoch_index: EpochIndex,
        random_seed: String,
        vrf_data: String,
        vrf_public_key: String,
        block_timestamp: BlockTimestamp,
    ) -> rpc::Result<String>;
}

#[async_trait::async_trait]
impl RpcTestFunctionsRpcServer for super::RpcTestFunctionsHandle {
    async fn genesis_pool_id(&self) -> rpc::Result<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_pool_id.hex_encode()),
        )
    }

    async fn genesis_private_key(&self) -> rpc::Result<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, genesis_stake_private_key, _, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_stake_private_key.hex_encode()),
        )
    }

    async fn genesis_public_key(&self) -> rpc::Result<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, genesis_stake_public_key, _, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_stake_public_key.hex_encode()),
        )
    }

    async fn genesis_vrf_private_key(&self) -> rpc::Result<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, genesis_vrf_private_key, _) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_vrf_private_key.hex_encode()),
        )
    }

    async fn genesis_vrf_public_key(&self) -> rpc::Result<Option<String>> {
        let (genesis_pool_id, genesis_stake_pool_data, _, _, _, genesis_vrf_public_key) =
            genesis_values(GenesisStakingSettings::default());

        Ok(
            assert_genesis_values(self, genesis_pool_id, genesis_stake_pool_data)
                .await
                .then_some(genesis_vrf_public_key.hex_encode()),
        )
    }

    async fn new_private_key(&self) -> rpc::Result<String> {
        let keys =
            crypto::key::PrivateKey::new_from_entropy(crypto::key::KeyKind::Secp256k1Schnorr);

        Ok(keys.0.hex_encode())
    }

    async fn public_key_from_private_key(&self, private_key_hex: String) -> rpc::Result<String> {
        let private_key =
            rpc::handle_result(crypto::key::PrivateKey::hex_decode_all(private_key_hex))?;

        let public_key = crypto::key::PublicKey::from_private_key(&private_key);

        Ok(public_key.hex_encode())
    }

    async fn sign_message_with_private_key(
        &self,
        private_key_hex: String,
        message_hex: String,
    ) -> rpc::Result<String> {
        let private_key: crypto::key::PrivateKey =
            rpc::handle_result(crypto::key::PrivateKey::hex_decode_all(private_key_hex))?;

        let message: Vec<u8> = rpc::handle_result(Vec::<u8>::hex_decode_all(message_hex))?;

        let signature = private_key.sign_message(&message).map_err(RpcTestFunctionsError::from);
        let signature: Signature = rpc::handle_result(signature)?;

        Ok(signature.hex_encode())
    }

    async fn verify_message_with_public_key(
        &self,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    ) -> rpc::Result<bool> {
        let public_key: crypto::key::PublicKey =
            rpc::handle_result(crypto::key::PublicKey::hex_decode_all(public_key_hex))?;

        let message: Vec<u8> = rpc::handle_result(Vec::<u8>::hex_decode_all(message_hex))?;
        let signature = rpc::handle_result(Signature::hex_decode_all(signature_hex))?;

        let verify_result = public_key.verify_message(&signature, &message);

        Ok(verify_result)
    }

    async fn new_vrf_private_key(&self) -> rpc::Result<String> {
        let keys =
            crypto::vrf::VRFPrivateKey::new_from_entropy(crypto::vrf::VRFKeyKind::Schnorrkel);

        Ok(keys.0.hex_encode())
    }

    async fn vrf_public_key_from_private_key(
        &self,
        private_key_hex: String,
    ) -> rpc::Result<String> {
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
    ) -> rpc::Result<String> {
        let random_seed: H256 = rpc::handle_result(H256::hex_decode_all(random_seed))?;

        let transcript = construct_transcript(
            epoch_index,
            &random_seed,
            BlockTimestamp::from_int_seconds(block_timestamp),
        );
        let private_key: crypto::vrf::VRFPrivateKey =
            rpc::handle_result(crypto::vrf::VRFPrivateKey::hex_decode_all(private_key_hex))?;

        let signature = private_key.produce_vrf_data(transcript.into());

        Ok(signature.hex_encode())
    }

    async fn verify_then_get_vrf_output(
        &self,
        epoch_index: EpochIndex,
        random_seed: String,
        vrf_data: String,
        vrf_public_key: String,
        block_timestamp: BlockTimestamp,
    ) -> rpc::Result<String> {
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
