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

mod interface;
mod server_impl;
pub mod types;

use chainstate::{ChainInfo, TokenIssuanceError};
use crypto::key::{hdkd::u31::U31, PublicKey};
use mempool::tx_accumulator::PackingStrategy;
use mempool_types::tx_options::TxOptionsOverrides;
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress, PeerId,
};
use serialization::hex_encoded::HexEncoded;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use utils::{ensure, shallow_clone::ShallowClone};
use wallet::{account::PartiallySignedTransaction, WalletError};

use common::{
    address::Address,
    chain::{
        tokens::{IsTokenFreezable, IsTokenUnfreezable, Metadata, TokenTotalSupply},
        Block, ChainConfig, DelegationId, GenBlock, PoolId, SignedTransaction, Transaction,
        TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, per_thousand::PerThousand, Amount, BlockHeight, DecimalAmount, Id},
};
pub use interface::WalletRpcServer;
pub use rpc::{rpc_creds::RpcCreds, Rpc, RpcAuthData};
use wallet_controller::{
    types::Balances, ConnectedPeer, ControllerConfig, ControllerError, NodeInterface, UtxoStates,
    UtxoTypes,
};
use wallet_types::{
    seed_phrase::StoreSeedPhrase,
    wallet_tx::{self, TxData},
    with_locked::WithLocked,
};

use crate::{
    service::{CreatedWallet, NodeRpcClient},
    WalletHandle, WalletRpcConfig,
};

pub use self::types::RpcError;
use self::types::{
    AddressInfo, AddressWithUsageInfo, BlockInfo, DelegationInfo, EmptyArgs, NewAccountInfo,
    NewDelegation, PoolInfo, PublicKeyInfo, VrfPublicKeyInfo,
};

pub struct WalletRpc {
    wallet: WalletHandle,
    node: NodeRpcClient,
    chain_config: Arc<ChainConfig>,
}

type WRpcResult<T> = Result<T, RpcError>;

impl WalletRpc {
    pub fn new(wallet: WalletHandle, node: NodeRpcClient, chain_config: Arc<ChainConfig>) -> Self {
        Self {
            wallet,
            node,
            chain_config,
        }
    }

    fn shutdown(&self) -> WRpcResult<()> {
        self.wallet.shallow_clone().stop().map_err(RpcError::SubmitError)
    }

    pub async fn create_wallet(
        &self,
        path: PathBuf,
        store_seed_phrase: StoreSeedPhrase,
        mnemonic: Option<String>,
    ) -> WRpcResult<CreatedWallet> {
        self.wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move {
                    wallet_manager.create_wallet(path, store_seed_phrase, mnemonic).await
                })
            })
            .await?
    }

    pub async fn open_wallet(
        &self,
        wallet_path: PathBuf,
        password: Option<String>,
    ) -> WRpcResult<()> {
        self.wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move { wallet_manager.open_wallet(wallet_path, password).await })
            })
            .await?
    }

    pub async fn close_wallet(&self) -> WRpcResult<()> {
        self.wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move { wallet_manager.close_wallet() })
            })
            .await?
    }

    pub async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        force_reduce: bool,
    ) -> WRpcResult<()> {
        self.wallet
            .call(move |w| w.set_lookahead_size(lookahead_size, force_reduce))
            .await?
    }

    pub async fn encrypt_private_keys(&self, password: String) -> WRpcResult<()> {
        self.wallet.call(|w| w.encrypt_wallet(&Some(password))).await?
    }

    pub async fn remove_private_key_encryption(&self) -> WRpcResult<()> {
        self.wallet.call(|w| w.encrypt_wallet(&None)).await?
    }

    pub async fn unlock_private_keys(&self, password: String) -> WRpcResult<()> {
        self.wallet.call(move |w| w.unlock_wallet(&password)).await?
    }

    pub async fn lock_private_keys(&self) -> WRpcResult<()> {
        self.wallet.call(|w| w.lock_wallet()).await?
    }

    async fn best_block(&self, _: EmptyArgs) -> WRpcResult<BlockInfo> {
        let res = self.wallet.call(|w| Ok::<_, RpcError>(w.best_block())).await??;
        Ok(BlockInfo::from_tuple(res))
    }

    pub async fn generate_block(
        &self,
        account_index: U31,
        transactions: Vec<SignedTransaction>,
    ) -> WRpcResult<Block> {
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.generate_block(
                        account_index,
                        transactions,
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await
                })
            })
            .await?
    }

    pub async fn generate_blocks(&self, account_index: U31, block_count: u32) -> WRpcResult<()> {
        self.wallet
            .call_async(move |w| {
                Box::pin(async move { w.generate_blocks(account_index, block_count).await })
            })
            .await?
    }

    pub async fn create_account(&self, name: Option<String>) -> WRpcResult<NewAccountInfo> {
        let (num, name) = self.wallet.call(|w| w.create_account(name)).await??;
        Ok(NewAccountInfo::new(num, name))
    }

    pub async fn issue_address(&self, account_index: U31) -> WRpcResult<AddressInfo> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let (child_number, destination) = self
            .wallet
            .call_async(move |w| {
                Box::pin(
                    async move { w.synced_controller(account_index, config).await?.new_address() },
                )
            })
            .await??;
        Ok(AddressInfo::new(child_number, destination))
    }

    pub async fn issue_public_key(&self, account_index: U31) -> WRpcResult<PublicKeyInfo> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let publick_key = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config).await?.new_public_key()
                })
            })
            .await??;
        Ok(PublicKeyInfo::new(publick_key))
    }

    pub async fn get_vrf_key(&self, account_index: U31) -> WRpcResult<VrfPublicKeyInfo> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let publick_key = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config).await?.get_vrf_public_key()
                })
            })
            .await??;
        Ok(VrfPublicKeyInfo::new(publick_key, &self.chain_config))
    }

    pub async fn get_issued_addresses(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<AddressWithUsageInfo>> {
        let addresses: BTreeMap<_, _> = self
            .wallet
            .call(move |controller| {
                controller.readonly_controller(account_index).get_addresses_with_usage()
            })
            .await??;
        let result = addresses
            .into_iter()
            .map(|(num, (addr, used))| AddressWithUsageInfo::new(num, addr, used))
            .collect();
        Ok(result)
    }

    pub async fn get_balance(
        &self,
        account_index: U31,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WRpcResult<Balances> {
        let balances: Balances = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let c = w.readonly_controller(account_index);
                    c.get_decimal_balance(utxo_states, with_locked).await
                })
            })
            .await??;
        Ok(balances)
    }

    pub async fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WRpcResult<Vec<(UtxoOutPoint, TxOutput)>> {
        self.wallet
            .call(move |w| {
                w.readonly_controller(account_index)
                    .get_utxos(utxo_types, utxo_states, with_locked)
            })
            .await?
    }

    pub async fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> WRpcResult<TxData> {
        self.wallet
            .call(move |controller| {
                controller
                    .readonly_controller(account_index)
                    .get_transaction(transaction_id)
                    .cloned()
            })
            .await?
    }

    pub async fn pending_transactions(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<WithId<Transaction>>> {
        self.wallet
            .call(move |w| {
                w.readonly_controller(account_index).pending_transactions().map(|txs| {
                    txs.into_iter().map(|tx| WithId::new(WithId::take(tx).clone())).collect()
                })
            })
            .await?
    }

    pub async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> WRpcResult<()> {
        self.node
            .submit_transaction(tx.take(), options)
            .await
            .map_err(RpcError::RpcError)
    }

    pub async fn sign_raw_transaction(
        &self,
        account_index: U31,
        tx: HexEncoded<PartiallySignedTransaction>,
        config: ControllerConfig,
    ) -> WRpcResult<HexEncoded<SignedTransaction>> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let tx = controller
                        .synced_controller(account_index, config)
                        .await?
                        .sign_raw_transaction(tx.take())?;
                    Ok::<HexEncoded<SignedTransaction>, ControllerError<_>>(tx)
                })
            })
            .await?
    }

    pub async fn send_coins(
        &self,
        account_index: U31,
        address: String,
        amount_str: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount_str.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_to_address(address, amount, selected_utxos)
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn send_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount_str: DecimalAmount,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let token_info = controller.get_token_info(token_id).await?;
                    let amount = amount_str
                        .to_amount(token_info.token_number_of_decimals())
                        .ok_or(RpcError::InvalidCoinAmount)?;

                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_tokens_to_address(token_info, address, amount)
                        .await?;
                    Ok::<(), RpcError>(())
                })
            })
            .await?
    }

    pub async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_key: Option<HexEncoded<PublicKey>>,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let cost_per_block =
            cost_per_block.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let decommission_key = decommission_key.map(HexEncoded::take);

        let margin_ratio_per_thousand = PerThousand::from_decimal_str(&margin_ratio_per_thousand)
            .ok_or(RpcError::InvalidMarginRatio)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_stake_pool_tx(
                            amount,
                            decommission_key,
                            margin_ratio_per_thousand,
                            cost_per_block,
                        )
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .decommission_stake_pool(pool_id)
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<HexEncoded<PartiallySignedTransaction>> {
        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let tx = controller
                        .synced_controller(account_index, config)
                        .await?
                        .decommission_stake_pool_request(pool_id)
                        .await?;
                    Ok::<HexEncoded<PartiallySignedTransaction>, ControllerError<_>>(tx)
                })
            })
            .await?
    }

    pub async fn create_delegation(
        &self,
        account_index: U31,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<NewDelegation> {
        let address =
            Address::from_str(&self.chain_config, &address).map_err(|_| RpcError::InvalidPoolId)?;

        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let delegation_id = controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_delegation(address, pool_id)
                        .await?;
                    Ok::<DelegationId, ControllerError<_>>(delegation_id)
                })
            })
            .await?
            .map(|delegation_id: DelegationId| NewDelegation {
                delegation_id: Address::new(&self.chain_config, &delegation_id)
                    .expect("addressable delegation id")
                    .get()
                    .to_owned(),
            })
    }

    pub async fn delegate_staking(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;

        let delegation_id = Address::from_str(&self.chain_config, &delegation_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .delegate_staking(amount, delegation_id)
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn send_from_delegation_to_address(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        let delegation_id = Address::from_str(&self.chain_config, &delegation_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_to_address_from_delegation(address, amount, delegation_id)
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn start_staking(&self, account_index: U31) -> WRpcResult<()> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.synced_controller(account_index, config).await?.start_staking()?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn stop_staking(&self, account_index: U31) -> WRpcResult<()> {
        self.wallet
            .call(move |controller| {
                controller.stop_staking(account_index)?;
                Ok::<(), ControllerError<_>>(())
            })
            .await?
    }

    pub async fn abandon_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> WRpcResult<()> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .abandon_transaction(transaction_id)
                })
            })
            .await?
    }

    pub async fn deposit_data(
        &self,
        account_index: U31,
        data: Vec<u8>,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .deposit_data(data)
                        .await?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_new_token(
        &self,
        account_index: U31,
        number_of_decimals: u8,
        destination_address: String,
        token_ticker: Vec<u8>,
        metadata_uri: Vec<u8>,
        token_total_supply: TokenTotalSupply,
        is_freezable: IsTokenFreezable,
        config: ControllerConfig,
    ) -> WRpcResult<String> {
        ensure!(
            number_of_decimals <= self.chain_config.token_max_dec_count(),
            RpcError::Controller(ControllerError::WalletError(WalletError::TokenIssuance(
                TokenIssuanceError::IssueErrorTooManyDecimals
            ),))
        );

        let destination_address = Address::from_str(&self.chain_config, &destination_address)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .issue_new_token(
                            destination_address,
                            token_ticker,
                            number_of_decimals,
                            metadata_uri,
                            token_total_supply,
                            is_freezable,
                        )
                        .await
                })
            })
            .await?
            .map(|token_id| {
                Address::new(&self.chain_config, &token_id)
                    .expect("Encoding token id should never fail")
                    .to_string()
            })
    }

    pub async fn issue_new_nft(
        &self,
        account_index: U31,
        address: String,
        metadata: Metadata,
        config: ControllerConfig,
    ) -> WRpcResult<String> {
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .issue_new_nft(address, metadata)
                        .await
                })
            })
            .await?
            .map(|token_id| {
                Address::new(&self.chain_config, &token_id)
                    .expect("Encoding token id should never fail")
                    .to_string()
            })
    }

    pub async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    let amount = amount
                        .to_amount(token_info.token_number_of_decimals())
                        .ok_or(RpcError::InvalidCoinAmount)?;

                    w.synced_controller(account_index, config)
                        .await?
                        .mint_tokens(token_info, amount, address)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    let amount = amount
                        .to_amount(token_info.token_number_of_decimals())
                        .ok_or(RpcError::InvalidCoinAmount)?;

                    w.synced_controller(account_index, config)
                        .await?
                        .unmint_tokens(token_info, amount)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .lock_token_supply(token_info)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn freeze_token(
        &self,
        account_index: U31,
        token_id: String,
        is_unfreezable: IsTokenUnfreezable,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .freeze_token(token_info, is_unfreezable)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .unfreeze_token(token_info)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> WRpcResult<()> {
        let token_id = Address::from_str(&self.chain_config, &token_id)
            .and_then(|address| address.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .change_token_authority(token_info, address)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn rescan(&self) -> WRpcResult<()> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.reset_wallet_to_genesis()?;
                    controller.sync_once().await
                })
            })
            .await?
    }

    pub async fn sync(&self) -> WRpcResult<()> {
        self.wallet
            .call_async(move |controller| Box::pin(async move { controller.sync_once().await }))
            .await?
    }

    pub async fn list_pool_ids(&self, account_index: U31) -> WRpcResult<Vec<PoolInfo>> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.readonly_controller(account_index).get_pool_ids().await
                })
            })
            .await?
            .map(|pools: Vec<(PoolId, wallet_tx::BlockInfo, Amount)>| {
                pools
                    .into_iter()
                    .map(|(pool_id, block_data, balance)| {
                        PoolInfo::new(pool_id, block_data, balance, &self.chain_config)
                    })
                    .collect()
            })
    }

    pub async fn list_delegation_ids(&self, account_index: U31) -> WRpcResult<Vec<DelegationInfo>> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.readonly_controller(account_index).get_delegations().await
                })
            })
            .await?
            .map(|delegations: Vec<(DelegationId, Amount)>| {
                delegations
                    .into_iter()
                    .map(|(delegation_id, balance)| {
                        DelegationInfo::new(delegation_id, balance, &self.chain_config)
                    })
                    .collect()
            })
    }

    pub async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<Id<GenBlock>>> {
        self.wallet
            .call(move |controller| {
                controller.readonly_controller(account_index).get_created_blocks()
            })
            .await?
    }

    pub async fn get_seed_phrase(&self) -> WRpcResult<Option<Vec<String>>> {
        self.wallet.call(move |controller| controller.seed_phrase()).await?
    }

    pub async fn purge_seed_phrase(&self) -> WRpcResult<Option<Vec<String>>> {
        self.wallet.call(move |controller| controller.delete_seed_phrase()).await?
    }

    pub async fn number_of_accounts(&self) -> WRpcResult<usize> {
        self.wallet
            .call(move |controller| Ok::<_, RpcError>(controller.account_names().count()))
            .await?
    }

    pub async fn account_names(&self) -> WRpcResult<Vec<Option<String>>> {
        self.wallet
            .call(move |controller| {
                Ok::<_, RpcError>(controller.account_names().cloned().collect())
            })
            .await?
    }

    pub async fn stake_pool_balance(&self, pool_id: String) -> WRpcResult<Option<String>> {
        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;
        Ok(self
            .node
            .get_stake_pool_balance(pool_id)
            .await
            .map_err(RpcError::RpcError)?
            .map(|balance| balance.into_fixedpoint_str(self.chain_config.coin_decimals())))
    }

    pub async fn node_version(&self) -> WRpcResult<String> {
        self.node.node_version().await.map_err(RpcError::RpcError)
    }

    pub async fn node_shutdown(&self) -> WRpcResult<()> {
        self.node.node_shutdown().await.map_err(RpcError::RpcError)
    }

    pub async fn connect_to_peer(&self, address: IpOrSocketAddress) -> WRpcResult<()> {
        self.node.p2p_connect(address).await.map_err(RpcError::RpcError)
    }

    pub async fn disconnect_peer(&self, peer_id: PeerId) -> WRpcResult<()> {
        self.node.p2p_disconnect(peer_id).await.map_err(RpcError::RpcError)
    }

    pub async fn list_banned(&self) -> WRpcResult<Vec<BannableAddress>> {
        self.node.p2p_list_banned().await.map_err(RpcError::RpcError)
    }

    pub async fn ban_address(&self, address: BannableAddress) -> WRpcResult<()> {
        self.node.p2p_ban(address).await.map_err(RpcError::RpcError)
    }

    pub async fn unban_address(&self, address: BannableAddress) -> WRpcResult<()> {
        self.node.p2p_unban(address).await.map_err(RpcError::RpcError)
    }

    pub async fn peer_count(&self) -> WRpcResult<usize> {
        self.node.p2p_get_peer_count().await.map_err(RpcError::RpcError)
    }

    pub async fn connected_peers(&self) -> WRpcResult<Vec<ConnectedPeer>> {
        self.node.p2p_get_connected_peers().await.map_err(RpcError::RpcError)
    }

    pub async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> WRpcResult<()> {
        self.node.p2p_add_reserved_node(address).await.map_err(RpcError::RpcError)
    }

    pub async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> WRpcResult<()> {
        self.node.p2p_remove_reserved_node(address).await.map_err(RpcError::RpcError)
    }

    pub async fn submit_block(&self, block: HexEncoded<Block>) -> WRpcResult<()> {
        self.node.submit_block(block.take()).await.map_err(RpcError::RpcError)
    }

    pub async fn chainstate_info(&self) -> WRpcResult<ChainInfo> {
        self.node.chainstate_info().await.map_err(RpcError::RpcError)
    }

    pub async fn node_best_block_id(&self) -> WRpcResult<Id<GenBlock>> {
        self.node.get_best_block_id().await.map_err(RpcError::RpcError)
    }

    pub async fn node_best_block_height(&self) -> WRpcResult<BlockHeight> {
        self.node.get_best_block_height().await.map_err(RpcError::RpcError)
    }

    pub async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> WRpcResult<Option<Id<GenBlock>>> {
        self.node.get_block_id_at_height(block_height).await.map_err(RpcError::RpcError)
    }

    pub async fn get_node_block(&self, block_id: Id<Block>) -> WRpcResult<Option<Block>> {
        self.node.get_block(block_id).await.map_err(RpcError::RpcError)
    }
}

pub async fn start(
    wallet_handle: WalletHandle,
    node_rpc: NodeRpcClient,
    config: WalletRpcConfig,
    chain_config: Arc<ChainConfig>,
) -> anyhow::Result<rpc::Rpc> {
    let WalletRpcConfig {
        bind_addr,
        auth_credentials,
    } = config;

    rpc::Builder::new(bind_addr, auth_credentials)
        .with_method_list("list_methods")
        .register(WalletRpc::new(wallet_handle, node_rpc, chain_config).into_rpc())
        .build()
        .await
}
