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

use std::{fmt::Debug, path::PathBuf, str::FromStr};

use chainstate::ChainInfo;
use common::{
    address::dehexify::{dehexify_all_addresses, to_dehexified_json},
    chain::{
        tokens::IsTokenUnfreezable, Block, GenBlock, SignedTransaction, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{BlockHeight, DecimalAmount, Id, Idable, H256},
};
use crypto::key::hdkd::u31::U31;
use node_comm::node_traits::NodeInterface;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded, json_encoded::JsonEncoded};
use utils_networking::IpOrSocketAddress;
use wallet::{
    account::{PartiallySignedTransaction, TxInfo},
    version::get_version,
};
use wallet_controller::{
    types::{CreatedBlockInfo, InspectTransaction, SeedWithPassPhrase, WalletInfo},
    ConnectedPeer, ControllerConfig,
};
use wallet_rpc_lib::{
    types::{
        AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, ComposedTransaction, CreatedWallet,
        DelegationInfo, LegacyVrfPublicKeyInfo, NewAccountInfo, NewDelegation, NewTransaction,
        NftMetadata, NodeVersion, PoolInfo, PublicKeyInfo, RpcTokenId, StakePoolBalance,
        StakingStatus, TokenMetadata, TxOptionsOverrides, UtxoInfo, VrfPublicKeyInfo,
    },
    RpcError, WalletRpc,
};
use wallet_types::{
    seed_phrase::StoreSeedPhrase,
    utxo_types::{UtxoStates, UtxoTypes},
    with_locked::WithLocked,
};

use crate::wallet_rpc_traits::{PartialOrSignedTx, WalletInterface};

pub struct WalletRpcHandlesClient<N: Clone> {
    wallet_rpc: WalletRpc<N>,
    server_rpc: Option<rpc::Rpc>,
}

#[derive(thiserror::Error, Debug)]
pub enum WalletRpcHandlesClientError<N: NodeInterface> {
    #[error("{0}")]
    WalletRpcError(#[from] wallet_rpc_lib::RpcError<N>),

    #[error("{0}")]
    SerializationError(#[from] serde_json::Error),
}

impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletRpcHandlesClient<N> {
    pub fn new(wallet_rpc: WalletRpc<N>, server_rpc: Option<rpc::Rpc>) -> Self {
        Self {
            wallet_rpc,
            server_rpc,
        }
    }
}

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletInterface
    for WalletRpcHandlesClient<N>
{
    type Error = WalletRpcHandlesClientError<N>;

    async fn exit(&mut self) -> Result<(), Self::Error> {
        if let Some(rpc) = self.server_rpc.take() {
            rpc.shutdown().await;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        if let Some(rpc) = self.server_rpc.take() {
            rpc.shutdown().await;
        }
        Ok(())
    }

    async fn version(&self) -> Result<String, Self::Error> {
        Ok(get_version())
    }

    async fn rpc_completed(&self) {
        self.wallet_rpc.closed().await
    }

    async fn create_wallet(
        &self,
        path: PathBuf,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    ) -> Result<CreatedWallet, Self::Error> {
        let whether_to_store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };
        self.wallet_rpc
            .create_wallet(path, whether_to_store_seed_phrase, mnemonic, passphrase)
            .await
            .map(|res| match res {
                wallet_rpc_lib::CreatedWallet::UserProvidedMnemonic => {
                    CreatedWallet::UserProvidedMnemonic
                }
                wallet_rpc_lib::CreatedWallet::NewlyGeneratedMnemonic(mnemonic, passphrase) => {
                    CreatedWallet::NewlyGeneratedMnemonic(mnemonic.to_string(), passphrase)
                }
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn open_wallet(
        &self,
        path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .open_wallet(path, password, force_migrate_wallet_type.unwrap_or(false))
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn close_wallet(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .close_wallet()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn wallet_info(&self) -> Result<WalletInfo, Self::Error> {
        self.wallet_rpc
            .wallet_info()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .sync()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn rescan(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .rescan()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        self.wallet_rpc
            .get_seed_phrase()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn purge_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        self.wallet_rpc
            .purge_seed_phrase()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .set_lookahead_size(lookahead_size, i_know_what_i_am_doing)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .encrypt_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_private_key_encryption()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unlock_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .lock_private_keys()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn best_block(&self) -> Result<BlockInfo, Self::Error> {
        self.wallet_rpc
            .best_block()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error> {
        self.wallet_rpc
            .create_account(name)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn rename_account(
        &self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<NewAccountInfo, Self::Error> {
        self.wallet_rpc
            .update_account_name(account_index, name)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_separate_address(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_separate_address(account_index, address, label)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_issued_addresses(
        &self,
        account_index: U31,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error> {
        self.wallet_rpc
            .get_issued_addresses(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_address(&self, account_index: U31) -> Result<AddressInfo, Self::Error> {
        self.wallet_rpc
            .issue_address(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reveal_public_key(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .find_public_key(account_index, address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_balance(
        &self,
        account_index: U31,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error> {
        self.wallet_rpc
            .get_balance(account_index, utxo_states, with_locked)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Vec<serde_json::Value>, Self::Error> {
        let utxos = self
            .wallet_rpc
            .get_utxos(account_index, utxo_types, utxo_states, with_locked)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)?;

        utxos
            .into_iter()
            .map(|utxo| {
                to_dehexified_json(self.wallet_rpc.chain_config(), UtxoInfo::from_tuple(utxo))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(WalletRpcHandlesClientError::SerializationError)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .submit_raw_transaction(tx, do_not_store, options)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sign_challenge(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .sign_challenge(account_index, challenge.into_bytes(), address)
            .await
            .map(|result| result.to_hex())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn transaction_from_cold_input(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxo: UtxoOutPoint,
        change_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<ComposedTransaction, Self::Error> {
        self.wallet_rpc
            .request_send_coins(
                account_index,
                address,
                amount.into(),
                selected_utxo,
                change_address,
                config,
            )
            .await
            .map(|(tx, fees)| ComposedTransaction {
                hex: HexEncoded::new(tx).to_string(),
                fees,
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn transaction_inspect(
        &self,
        transaction: String,
    ) -> Result<InspectTransaction, Self::Error> {
        self.wallet_rpc
            .transaction_inspect(transaction)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sign_challenge_hex(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        let challenge = hex::decode(challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .sign_challenge(account_index, challenge, address)
            .await
            .map(|result| result.to_hex())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        let signed_challenge =
            hex::decode(signed_challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .verify_challenge(message.into_bytes(), signed_challenge, address)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn verify_challenge_hex(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        let message = hex::decode(message).map_err(|_| RpcError::<N>::InvalidHexData)?;
        let signed_challenge =
            hex::decode(signed_challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .verify_challenge(message, signed_challenge, address)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        only_transaction: bool,
    ) -> Result<ComposedTransaction, Self::Error> {
        self.wallet_rpc
            .compose_transaction(inputs, outputs, only_transaction)
            .await
            .map(|(tx, fees)| ComposedTransaction {
                hex: tx.to_hex(),
                fees,
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_coins(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .send_coins(
                account_index,
                address,
                amount.into(),
                selected_utxos,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sweep_addresses(
        &self,
        account_index: U31,
        destination_address: String,
        from_addresses: Vec<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .sweep_addresses(account_index, destination_address, from_addresses, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sweep_delegation(
        &self,
        account_index: U31,
        destination_address: String,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .sweep_delegation(account_index, destination_address, delegation_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .create_stake_pool(
                account_index,
                amount.into(),
                cost_per_block.into(),
                margin_ratio_per_thousand,
                decommission_address,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .decommission_stake_pool(account_index, pool_id, output_address, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<HexEncoded<PartiallySignedTransaction>, Self::Error> {
        self.wallet_rpc
            .decommission_stake_pool_request(account_index, pool_id, output_address, config)
            .await
            .map(HexEncoded::new)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_delegation(
        &self,
        account_index: U31,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegation, Self::Error> {
        self.wallet_rpc
            .create_delegation(account_index, address, pool_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn delegate_staking(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .delegate_staking(account_index, amount.into(), delegation_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn withdraw_from_delegation(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .withdraw_from_delegation(account_index, address, amount.into(), delegation_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn start_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        self.wallet_rpc
            .start_staking(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stop_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        self.wallet_rpc
            .stop_staking(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn staking_status(&self, account_index: U31) -> Result<StakingStatus, Self::Error> {
        self.wallet_rpc
            .staking_status(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_staking_pools(&self, account_index: U31) -> Result<Vec<PoolInfo>, Self::Error> {
        self.wallet_rpc
            .list_staking_pools(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pools_for_decommission(
        &self,
        account_index: U31,
    ) -> Result<Vec<PoolInfo>, Self::Error> {
        self.wallet_rpc
            .list_pools_for_decommission(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error> {
        self.wallet_rpc
            .stake_pool_balance(pool_id)
            .await
            .map(|balance| StakePoolBalance { balance })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_delegation_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<DelegationInfo>, Self::Error> {
        self.wallet_rpc
            .list_delegation_ids(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<CreatedBlockInfo>, Self::Error> {
        self.wallet_rpc
            .list_created_blocks_ids(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn new_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<VrfPublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .issue_vrf_key(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error> {
        self.wallet_rpc
            .get_vrf_key_usage(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<LegacyVrfPublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .get_legacy_vrf_public_key(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_nft(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        self.wallet_rpc
            .issue_new_nft(
                account_index,
                destination_address,
                metadata.into_metadata(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_token(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let token_supply = metadata.token_supply()?;
        let is_freezable = metadata.is_freezable();
        self.wallet_rpc
            .issue_new_token(
                account_index,
                metadata.number_of_decimals,
                destination_address,
                metadata.token_ticker.into_bytes(),
                metadata.metadata_uri.into_bytes(),
                token_supply,
                is_freezable,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .change_token_authority(account_index, token_id, address, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .mint_tokens(account_index, token_id, address, amount.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .unmint_tokens(account_index, token_id, amount.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .lock_token_supply(account_index, token_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn freeze_token(
        &self,
        account_index: U31,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let is_unfreezable = if is_unfreezable {
            IsTokenUnfreezable::Yes
        } else {
            IsTokenUnfreezable::No
        };
        self.wallet_rpc
            .freeze_token(account_index, token_id, is_unfreezable, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .unfreeze_token(account_index, token_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .send_tokens(account_index, token_id, address, amount.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn deposit_data(
        &self,
        account_index: U31,
        data: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let data = hex::decode(data).map_err(|_| RpcError::<N>::InvalidHexData)?;

        self.wallet_rpc
            .deposit_data(account_index, data, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_version(&self) -> Result<NodeVersion, Self::Error> {
        self.wallet_rpc
            .node_version()
            .await
            .map(|version| NodeVersion { version })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .node_shutdown()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error> {
        self.wallet_rpc
            .node_enable_networking(enable)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .connect_to_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn disconnect_peer(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        self.wallet_rpc
            .disconnect_peer(peer_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_banned(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_banned()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .ban_address(address, duration)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unban_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unban_address(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_discouraged(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_discouraged()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn peer_count(&self) -> Result<usize, Self::Error> {
        self.wallet_rpc
            .peer_count()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        self.wallet_rpc
            .connected_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reserved_peers(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        self.wallet_rpc
            .reserved_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> Result<(), Self::Error> {
        self.wallet_rpc
            .submit_block(block)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        self.wallet_rpc
            .chainstate_info()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn abandon_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .abandon_transaction(account_index, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pending_transactions(
        &self,
        account_index: U31,
    ) -> Result<Vec<Id<Transaction>>, Self::Error> {
        self.wallet_rpc
            .pending_transactions(account_index)
            .await
            .map(|txs| txs.into_iter().map(|tx| tx.get_id()).collect::<Vec<_>>())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_transactions_by_address(
        &self,
        account_index: U31,
        address: Option<String>,
        limit: usize,
    ) -> Result<Vec<TxInfo>, Self::Error> {
        self.wallet_rpc
            .mainchain_transactions(account_index, address, limit)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .and_then(|tx| {
                let str = JsonEncoded::new((tx.get_transaction(), tx.state())).to_string();
                let str = dehexify_all_addresses(self.wallet_rpc.chain_config(), &str);
                serde_json::from_str::<serde_json::Value>(&str)
                    .map_err(WalletRpcHandlesClientError::SerializationError)
            })
    }

    async fn get_raw_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_signed_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: String,
        config: ControllerConfig,
    ) -> Result<PartialOrSignedTx, Self::Error> {
        self.wallet_rpc
            .sign_raw_transaction(account_index, raw_tx, config)
            .await
            .map(|ptx| {
                if ptx.is_fully_signed() {
                    PartialOrSignedTx::Signed(ptx.into_signed_tx().expect("already checked"))
                } else {
                    PartialOrSignedTx::Partial(ptx)
                }
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.wallet_rpc
            .node_best_block_id()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet_rpc
            .node_best_block_height()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        self.wallet_rpc
            .node_block_id(block_height)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_generate_block(
        &self,
        account_index: U31,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .generate_block(
                account_index,
                transactions.into_iter().map(HexEncoded::take).collect(),
            )
            .await
            .map(|_| ())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_generate_blocks(
        &self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .generate_blocks(account_index, block_count)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_block(&self, block_id: String) -> Result<Option<String>, Self::Error> {
        let hash = H256::from_str(&block_id).map_err(|_| RpcError::<N>::InvalidBlockId)?;
        self.wallet_rpc
            .get_node_block(hash.into())
            .await
            .map(|block_opt| block_opt.map(|block| block.hex_encode()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }
}
