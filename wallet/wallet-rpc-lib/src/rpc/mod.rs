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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    num::{NonZeroU8, NonZeroUsize},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use chainstate::{tx_verifier::check_transaction, ChainInfo, TokenIssuanceError};
use crypto::key::{hdkd::u31::U31, PrivateKey, PublicKey};
use mempool::tx_accumulator::PackingStrategy;
use mempool_types::tx_options::TxOptionsOverrides;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use serialization::{hex_encoded::HexEncoded, Decode, DecodeAll};
use utils::{ensure, shallow_clone::ShallowClone};
use utils_networking::IpOrSocketAddress;
use wallet::{
    account::{PartiallySignedTransaction, PoolData, TransactionToSign, TxInfo},
    WalletError,
};

use common::{
    address::Address,
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        signature::inputsig::arbitrary_message::{
            produce_message_challenge, ArbitraryMessageSignature,
        },
        tokens::{IsTokenFreezable, IsTokenUnfreezable, Metadata, TokenId, TokenTotalSupply},
        Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId, SignedTransaction,
        Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{
        id::WithId, per_thousand::PerThousand, time::Time, Amount, BlockHeight, Id, Idable,
    },
};
pub use interface::{
    ColdWalletRpcClient, ColdWalletRpcDescription, ColdWalletRpcServer, WalletEventsRpcServer,
    WalletRpcClient, WalletRpcDescription, WalletRpcServer,
};
pub use rpc::{rpc_creds::RpcCreds, Rpc};
use wallet_controller::{
    types::{
        Balances, BlockInfo, CreatedBlockInfo, InspectTransaction, SeedWithPassPhrase,
        TransactionToInspect, WalletInfo,
    },
    ConnectedPeer, ControllerConfig, ControllerError, NodeInterface, UtxoStates, UtxoTypes,
    DEFAULT_ACCOUNT_INDEX,
};
use wallet_types::{seed_phrase::StoreSeedPhrase, wallet_tx::TxData, with_locked::WithLocked};

use crate::{service::CreatedWallet, WalletHandle, WalletRpcConfig};

pub use self::types::RpcError;
use self::types::{
    AddressInfo, AddressWithUsageInfo, DelegationInfo, LegacyVrfPublicKeyInfo, NewAccountInfo,
    NewDelegation, NewTransaction, PoolInfo, PublicKeyInfo, RpcAddress, RpcAmountIn, RpcHexString,
    RpcTokenId, StakingStatus, VrfPublicKeyInfo,
};

#[derive(Clone)]
pub struct WalletRpc<N: Clone> {
    wallet: WalletHandle<N>,
    node: N,
    chain_config: Arc<ChainConfig>,
}

type WRpcResult<T, N> = Result<T, RpcError<N>>;

impl<N: NodeInterface + Clone + Send + Sync + 'static> WalletRpc<N> {
    pub fn new(wallet: WalletHandle<N>, node: N, chain_config: Arc<ChainConfig>) -> Self {
        Self {
            wallet,
            node,
            chain_config,
        }
    }

    pub async fn closed(&self) {
        self.wallet.closed().await
    }

    pub fn chain_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    fn shutdown(&self) -> WRpcResult<(), N> {
        self.wallet.shallow_clone().stop().map_err(RpcError::SubmitError)
    }

    pub async fn create_wallet(
        &self,
        path: PathBuf,
        store_seed_phrase: StoreSeedPhrase,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    ) -> WRpcResult<CreatedWallet, N> {
        self.wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move {
                    wallet_manager
                        .create_wallet(path, store_seed_phrase, mnemonic, passphrase)
                        .await
                })
            })
            .await?
    }

    pub async fn open_wallet(
        &self,
        wallet_path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: bool,
    ) -> WRpcResult<(), N> {
        Ok(self
            .wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move {
                    wallet_manager
                        .open_wallet(wallet_path, password, force_migrate_wallet_type)
                        .await
                })
            })
            .await??)
    }

    pub async fn close_wallet(&self) -> WRpcResult<(), N> {
        Ok(self
            .wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move { wallet_manager.close_wallet() })
            })
            .await??)
    }

    pub async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        force_reduce: bool,
    ) -> WRpcResult<(), N> {
        self.wallet
            .call(move |w| w.set_lookahead_size(lookahead_size, force_reduce))
            .await?
    }

    pub async fn encrypt_private_keys(&self, password: String) -> WRpcResult<(), N> {
        self.wallet.call(|w| w.encrypt_wallet(&Some(password))).await?
    }

    pub async fn remove_private_key_encryption(&self) -> WRpcResult<(), N> {
        self.wallet.call(|w| w.encrypt_wallet(&None)).await?
    }

    pub async fn unlock_private_keys(&self, password: String) -> WRpcResult<(), N> {
        self.wallet.call(move |w| w.unlock_wallet(&password)).await?
    }

    pub async fn lock_private_keys(&self) -> WRpcResult<(), N> {
        self.wallet.call(|w| w.lock_wallet()).await?
    }

    pub async fn best_block(&self) -> WRpcResult<BlockInfo, N> {
        let res = self.wallet.call(|w| Ok::<_, RpcError<N>>(w.best_block())).await??;
        Ok(BlockInfo::from_tuple(res))
    }

    pub async fn generate_block(
        &self,
        account_index: U31,
        transactions: Vec<SignedTransaction>,
    ) -> WRpcResult<Block, N> {
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

    pub async fn generate_blocks(&self, account_index: U31, block_count: u32) -> WRpcResult<(), N> {
        self.wallet
            .call_async(move |w| {
                Box::pin(async move { w.generate_blocks(account_index, block_count).await })
            })
            .await?
    }

    pub async fn create_account(&self, name: Option<String>) -> WRpcResult<NewAccountInfo, N> {
        let (num, name) = self.wallet.call(|w| w.create_account(name)).await??;
        Ok(NewAccountInfo::new(num, name))
    }

    pub async fn update_account_name(
        &self,
        account_index: U31,
        name: Option<String>,
    ) -> WRpcResult<NewAccountInfo, N> {
        let (num, name) =
            self.wallet.call(move |w| w.update_account_name(account_index, name)).await??;
        Ok(NewAccountInfo::new(num, name))
    }

    pub async fn add_standalone_watch_only_address(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
    ) -> WRpcResult<(), N> {
        let dest = Address::from_string(&self.chain_config, &address)
            .map(|addr| addr.into_object())
            .map_err(|_| RpcError::InvalidAddress)?;
        let pkh = match dest {
            Destination::PublicKeyHash(pkh) => pkh,
            Destination::PublicKey(pk) => (&pk).into(),
            Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_)
            | Destination::AnyoneCanSpend => return Err(RpcError::InvalidAddress),
        };

        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .add_standalone_address(pkh, label)
                })
            })
            .await??;
        Ok(())
    }

    pub async fn add_standalone_private_key(
        &self,
        account_index: U31,
        private_key: PrivateKey,
        label: Option<String>,
    ) -> WRpcResult<(), N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .add_standalone_private_key(private_key, label)
                })
            })
            .await??;
        Ok(())
    }

    pub async fn add_standalone_multisig(
        &self,
        account_index: U31,
        min_required_signatures: u8,
        public_keys: Vec<String>,
        label: Option<String>,
    ) -> WRpcResult<String, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        let min_required_signatures =
            NonZeroU8::new(min_required_signatures).ok_or(RpcError::InvalidAddress)?;

        let public_keys = public_keys
            .into_iter()
            .map(|addr| {
                Address::from_string(&self.chain_config, addr)
                    .map_err(|_| RpcError::InvalidAddress)
                    .and_then(|dest| match dest.into_object() {
                        Destination::PublicKey(pk) => Ok(pk),
                        _ => Err(RpcError::MultisigNotPublicKey),
                    })
            })
            .collect::<WRpcResult<Vec<PublicKey>, N>>()?;

        let challenge = ClassicMultisigChallenge::new(
            &self.chain_config,
            min_required_signatures,
            public_keys,
        )?;

        let multisig_address = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .add_standalone_multisig(challenge, label)
                })
            })
            .await??;
        let address = Address::new(
            &self.chain_config,
            Destination::ClassicMultisig(multisig_address),
        )
        .expect("addressable");

        Ok(address.to_string())
    }

    pub async fn issue_address(&self, account_index: U31) -> WRpcResult<AddressInfo, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
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

    pub async fn find_public_key(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
    ) -> WRpcResult<PublicKeyInfo, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        let address = address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let public_key = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config).await?.find_public_key(address)
                })
            })
            .await??;
        Ok(PublicKeyInfo::new(public_key, &self.chain_config))
    }

    pub async fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> WRpcResult<LegacyVrfPublicKeyInfo, N> {
        self.wallet
            .call_async(move |w| {
                Box::pin(
                    async move { w.readonly_controller(account_index).get_legacy_vrf_public_key() },
                )
            })
            .await?
            .map(|vrf_public_key| LegacyVrfPublicKeyInfo {
                vrf_public_key: vrf_public_key.to_string(),
            })
    }

    pub async fn issue_vrf_key(&self, account_index: U31) -> WRpcResult<VrfPublicKeyInfo, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        self.wallet
            .call_async(move |w| {
                Box::pin(
                    async move { w.synced_controller(account_index, config).await?.new_vrf_key() },
                )
            })
            .await?
            .map(|(child_number, vrf_key)| VrfPublicKeyInfo::new(vrf_key, child_number, false))
    }

    pub async fn get_vrf_key_usage(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<VrfPublicKeyInfo>, N> {
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.readonly_controller(account_index).get_all_issued_vrf_public_keys()
                })
            })
            .await?
            .map(|keys| {
                keys.into_iter()
                    .map(|(child_number, (pub_key, used))| {
                        VrfPublicKeyInfo::new(pub_key, child_number, used)
                    })
                    .collect()
            })
    }

    pub async fn get_issued_addresses(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<AddressWithUsageInfo>, N> {
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
    ) -> WRpcResult<Balances, N> {
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

    pub async fn get_multisig_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WRpcResult<Vec<(UtxoOutPoint, TxOutput)>, N> {
        self.wallet
            .call(move |w| {
                w.readonly_controller(account_index).get_multisig_utxos(
                    utxo_types,
                    utxo_states,
                    with_locked,
                )
            })
            .await?
    }

    pub async fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WRpcResult<Vec<(UtxoOutPoint, TxOutput)>, N> {
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
    ) -> WRpcResult<TxData, N> {
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
    ) -> WRpcResult<Vec<WithId<Transaction>>, N> {
        self.wallet
            .call(move |w| {
                w.readonly_controller(account_index).pending_transactions().map(|txs| {
                    txs.into_iter().map(|tx| WithId::new(WithId::take(tx).clone())).collect()
                })
            })
            .await?
    }

    pub async fn mainchain_transactions(
        &self,
        account_index: U31,
        address: Option<RpcAddress<Destination>>,
        limit: usize,
    ) -> WRpcResult<Vec<TxInfo>, N> {
        let address = address
            .map(|a| a.decode_object(&self.chain_config))
            .transpose()
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call(move |w| {
                w.readonly_controller(account_index).mainchain_transactions(address, limit)
            })
            .await?
    }

    pub async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> WRpcResult<NewTransaction, N> {
        let tx = tx.take();
        let block_height = self.best_block().await?.height;
        check_transaction(&self.chain_config, block_height, &tx).map_err(|err| {
            RpcError::Controller(ControllerError::WalletError(
                WalletError::InvalidTransaction(err),
            ))
        })?;
        let tx_id = tx.transaction().get_id();
        self.node
            .submit_transaction(tx.clone(), options)
            .await
            .map_err(RpcError::RpcError)?;

        let store_tx_in_wallet = !do_not_store;
        if store_tx_in_wallet {
            let config = ControllerConfig {
                in_top_x_mb: 5,
                broadcast_to_mempool: true,
            }; // irrelevant for issuing addresses
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller
                            .synced_controller(DEFAULT_ACCOUNT_INDEX, config)
                            .await?
                            .add_unconfirmed_tx(tx)
                            .map_err(RpcError::Controller)
                    })
                })
                .await??;
        }

        Ok(NewTransaction { tx_id })
    }

    pub async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: RpcHexString,
        config: ControllerConfig,
    ) -> WRpcResult<PartiallySignedTransaction, N> {
        let mut bytes = raw_tx.as_ref();
        let tx = Transaction::decode(&mut bytes).map_err(|_| RpcError::InvalidRawTransaction)?;
        let tx_to_sign = if bytes.is_empty() {
            TransactionToSign::Tx(tx)
        } else {
            let mut bytes = raw_tx.as_ref();
            let ptx = PartiallySignedTransaction::decode_all(&mut bytes)
                .map_err(|_| RpcError::InvalidPartialTransaction)?;
            TransactionToSign::Partial(ptx)
        };

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .sign_raw_transaction(tx_to_sign)
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn sign_challenge(
        &self,
        account_index: U31,
        challenge: Vec<u8>,
        address: RpcAddress<Destination>,
    ) -> WRpcResult<ArbitraryMessageSignature, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        let destination = address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .sign_challenge(challenge, destination)
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub fn verify_challenge(
        &self,
        message: Vec<u8>,
        signed_challenge: Vec<u8>,
        address: RpcAddress<Destination>,
    ) -> WRpcResult<(), N> {
        let destination = address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let message_challenge = produce_message_challenge(&message);
        let sig = ArbitraryMessageSignature::from_data(signed_challenge);
        sig.verify_signature(&self.chain_config, &destination, &message_challenge)?;

        Ok(())
    }

    pub async fn sweep_addresses(
        &self,
        account_index: U31,
        destination_address: RpcAddress<Destination>,
        from_addresses: Vec<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let destination_address = destination_address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let from_addresses = from_addresses
            .into_iter()
            .map(|a| a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress))
            .collect::<Result<BTreeSet<Destination>, _>>()?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .sweep_addresses(destination_address, from_addresses)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn sweep_delegation(
        &self,
        account_index: U31,
        destination_address: RpcAddress<Destination>,
        delegation_id: RpcAddress<DelegationId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let delegation_id = delegation_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidPoolId)?;
        let destination_address = destination_address
            .into_address(self.chain_config())
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .sweep_delegation(destination_address, delegation_id)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn send_coins(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_to_address(address, amount, selected_utxos)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn request_send_coins(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxo: UtxoOutPoint,
        change_address: Option<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<(PartiallySignedTransaction, Balances), N> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;
        let change_address = change_address
            .map(|change| change.into_address(&self.chain_config))
            .transpose()
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .request_send_to_address(address, amount, selected_utxo, change_address)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn transaction_inspect(
        &self,
        raw_tx: RpcHexString,
    ) -> WRpcResult<InspectTransaction, N> {
        let hex_bytes = raw_tx.into_bytes();
        let mut bytes = hex_bytes.as_slice();
        let tx = Transaction::decode(&mut bytes).map_err(|_| RpcError::InvalidRawTransaction)?;
        let tx: TransactionToInspect = if bytes.is_empty() {
            TransactionToInspect::Tx(tx)
        } else {
            let mut bytes = hex_bytes.as_slice();
            if let Ok(ptx) = PartiallySignedTransaction::decode_all(&mut bytes) {
                TransactionToInspect::Partial(ptx)
            } else {
                let mut bytes = hex_bytes.as_slice();
                let stx = SignedTransaction::decode_all(&mut bytes)
                    .map_err(|_| RpcError::InvalidPartialTransaction)?;
                TransactionToInspect::Signed(stx)
            }
        };

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.inspect_transaction(tx).await.map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn send_tokens(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let token_info = controller.get_token_info(token_id).await?;
                    let amount = amount
                        .to_amount(token_info.token_number_of_decimals())
                        .ok_or(RpcError::InvalidCoinAmount)?;

                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_tokens_to_address(token_info, address, amount)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: RpcAmountIn,
        cost_per_block: RpcAmountIn,
        margin_ratio_per_thousand: String,
        decommission_address: RpcAddress<Destination>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let cost_per_block =
            cost_per_block.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;

        let margin_ratio_per_thousand = PerThousand::from_decimal_str(&margin_ratio_per_thousand)
            .map_err(|_| RpcError::InvalidMarginRatio)?;

        let decommission_destination = decommission_address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_stake_pool_tx(
                            amount,
                            decommission_destination,
                            margin_ratio_per_thousand,
                            cost_per_block,
                        )
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let pool_id =
            pool_id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidPoolId)?;

        let output_address = output_address
            .map(|a| a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress))
            .transpose()?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .decommission_stake_pool(pool_id, output_address)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<PartiallySignedTransaction, N> {
        let pool_id =
            pool_id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidPoolId)?;

        let output_address = output_address
            .map(|a| a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress))
            .transpose()?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .decommission_stake_pool_request(pool_id, output_address)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn create_delegation(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        pool_id: RpcAddress<PoolId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewDelegation, N> {
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;

        let pool_id =
            pool_id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_delegation(address, pool_id)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
            .map(|(tx, delegation_id)| NewDelegation {
                tx_id: tx.transaction().get_id(),
                delegation_id: RpcAddress::new(&self.chain_config, delegation_id)
                    .expect("addressable delegation id"),
            })
    }

    pub async fn delegate_staking(
        &self,
        account_index: U31,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;

        let delegation_id = delegation_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidDelegationId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .delegate_staking(amount, delegation_id)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn withdraw_from_delegation(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;
        let delegation_id = delegation_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidDelegationId)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .send_to_address_from_delegation(address, amount, delegation_id)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn start_staking(&self, account_index: U31) -> WRpcResult<(), N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.synced_controller(account_index, config).await?.start_staking()?;
                    Ok::<(), ControllerError<_>>(())
                })
            })
            .await?
    }

    pub async fn stop_staking(&self, account_index: U31) -> WRpcResult<(), N> {
        self.wallet
            .call(move |controller| {
                controller.stop_staking(account_index)?;
                Ok::<(), ControllerError<_>>(())
            })
            .await?
    }

    pub async fn staking_status(&self, account_index: U31) -> WRpcResult<StakingStatus, N> {
        self.wallet
            .call(move |controller| {
                let status = StakingStatus::new(controller.is_staking(account_index));
                Ok::<_, ControllerError<_>>(status)
            })
            .await?
    }

    pub async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        only_transaction: bool,
    ) -> WRpcResult<(TransactionToSign, Balances), N> {
        ensure!(!inputs.is_empty(), RpcError::ComposeTransactionEmptyInputs);
        self.wallet
            .call_async(move |w| {
                Box::pin(
                    async move { w.compose_transaction(inputs, outputs, only_transaction).await },
                )
            })
            .await?
    }

    pub async fn abandon_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> WRpcResult<(), N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
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
    ) -> WRpcResult<NewTransaction, N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .deposit_data(data)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_new_token(
        &self,
        account_index: U31,
        number_of_decimals: u8,
        destination_address: RpcAddress<Destination>,
        token_ticker: Vec<u8>,
        metadata_uri: Vec<u8>,
        token_total_supply: TokenTotalSupply,
        is_freezable: IsTokenFreezable,
        config: ControllerConfig,
    ) -> WRpcResult<RpcTokenId, N> {
        ensure!(
            number_of_decimals <= self.chain_config.token_max_dec_count(),
            RpcError::Controller(ControllerError::WalletError(WalletError::TokenIssuance(
                TokenIssuanceError::IssueErrorTooManyDecimals
            ),))
        );

        let destination_address = destination_address
            .into_address(&self.chain_config)
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
            .map(|(tx, token_id)| RpcTokenId {
                tx_id: tx.transaction().get_id(),
                token_id: RpcAddress::new(&self.chain_config, token_id)
                    .expect("Encoding token id should never fail"),
            })
    }

    pub async fn issue_new_nft(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        metadata: Metadata,
        config: ControllerConfig,
    ) -> WRpcResult<RpcTokenId, N> {
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;
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
            .map(|(tx, token_id)| RpcTokenId {
                tx_id: tx.transaction().get_id(),
                token_id: RpcAddress::new(&self.chain_config, token_id)
                    .expect("Encoding token id should never fail"),
            })
    }

    pub async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;

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
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        amount: RpcAmountIn,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
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
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
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
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn freeze_token(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        is_unfreezable: IsTokenUnfreezable,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
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
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
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
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        config: ControllerConfig,
    ) -> WRpcResult<NewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        let address =
            address.into_address(&self.chain_config).map_err(|_| RpcError::InvalidAddress)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .change_token_authority(token_info, address)
                        .await
                        .map_err(RpcError::Controller)
                        .map(NewTransaction::new)
                })
            })
            .await?
    }

    pub async fn rescan(&self) -> WRpcResult<(), N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.reset_wallet_to_genesis()?;
                    controller.sync_once().await
                })
            })
            .await?
    }

    pub async fn sync(&self) -> WRpcResult<(), N> {
        self.wallet
            .call_async(move |controller| Box::pin(async move { controller.sync_once().await }))
            .await?
    }

    pub async fn list_staking_pools(&self, account_index: U31) -> WRpcResult<Vec<PoolInfo>, N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.readonly_controller(account_index).get_staking_pools().await
                })
            })
            .await?
            .map(|pools: Vec<(PoolId, PoolData, Amount, Amount)>| {
                pools
                    .into_iter()
                    .map(|(pool_id, pool_data, balance, pledge)| {
                        PoolInfo::new(pool_id, pool_data, balance, pledge, &self.chain_config)
                    })
                    .collect()
            })
    }

    pub async fn list_pools_for_decommission(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<PoolInfo>, N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.readonly_controller(account_index).get_pools_for_decommission().await
                })
            })
            .await?
            .map(|pools: Vec<(PoolId, PoolData, Amount, Amount)>| {
                pools
                    .into_iter()
                    .map(|(pool_id, pool_data, balance, pledge)| {
                        PoolInfo::new(pool_id, pool_data, balance, pledge, &self.chain_config)
                    })
                    .collect()
            })
    }

    pub async fn list_delegation_ids(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<DelegationInfo>, N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller.readonly_controller(account_index).get_delegations().await
                })
            })
            .await?
            .map(|delegations: Vec<(DelegationId, PoolId, Amount)>| {
                delegations
                    .into_iter()
                    .map(|(delegation_id, _, balance)| {
                        DelegationInfo::new(delegation_id, balance, &self.chain_config)
                    })
                    .collect()
            })
    }

    pub async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> WRpcResult<Vec<CreatedBlockInfo>, N> {
        self.wallet
            .call(move |controller| {
                controller.readonly_controller(account_index).get_created_blocks()
            })
            .await?
    }

    pub async fn get_seed_phrase(&self) -> WRpcResult<Option<SeedWithPassPhrase>, N> {
        self.wallet.call(move |controller| controller.seed_phrase()).await?
    }

    pub async fn purge_seed_phrase(&self) -> WRpcResult<Option<SeedWithPassPhrase>, N> {
        self.wallet.call(move |controller| controller.delete_seed_phrase()).await?
    }

    pub async fn wallet_info(&self) -> WRpcResult<WalletInfo, N> {
        self.wallet
            .call(move |controller| Ok::<_, RpcError<N>>(controller.wallet_info()))
            .await?
    }

    pub async fn stake_pool_balance(
        &self,
        pool_id: RpcAddress<PoolId>,
    ) -> WRpcResult<Option<String>, N> {
        let pool_id =
            pool_id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidPoolId)?;
        Ok(self
            .node
            .get_stake_pool_balance(pool_id)
            .await
            .map_err(RpcError::RpcError)?
            .map(|balance| balance.into_fixedpoint_str(self.chain_config.coin_decimals())))
    }

    pub async fn node_version(&self) -> WRpcResult<String, N> {
        self.node.node_version().await.map_err(RpcError::RpcError)
    }

    pub async fn node_shutdown(&self) -> WRpcResult<(), N> {
        self.node.node_shutdown().await.map_err(RpcError::RpcError)
    }

    pub async fn node_enable_networking(&self, enable: bool) -> WRpcResult<(), N> {
        self.node.node_enable_networking(enable).await.map_err(RpcError::RpcError)
    }

    pub async fn connect_to_peer(&self, address: IpOrSocketAddress) -> WRpcResult<(), N> {
        self.node.p2p_connect(address).await.map_err(RpcError::RpcError)
    }

    pub async fn disconnect_peer(&self, peer_id: PeerId) -> WRpcResult<(), N> {
        self.node.p2p_disconnect(peer_id).await.map_err(RpcError::RpcError)
    }

    pub async fn list_banned(&self) -> WRpcResult<Vec<(BannableAddress, Time)>, N> {
        self.node.p2p_list_banned().await.map_err(RpcError::RpcError)
    }

    pub async fn ban_address(
        &self,
        address: BannableAddress,
        duration: Duration,
    ) -> WRpcResult<(), N> {
        self.node.p2p_ban(address, duration).await.map_err(RpcError::RpcError)
    }

    pub async fn unban_address(&self, address: BannableAddress) -> WRpcResult<(), N> {
        self.node.p2p_unban(address).await.map_err(RpcError::RpcError)
    }

    pub async fn list_discouraged(&self) -> WRpcResult<Vec<(BannableAddress, Time)>, N> {
        self.node.p2p_list_discouraged().await.map_err(RpcError::RpcError)
    }

    pub async fn peer_count(&self) -> WRpcResult<usize, N> {
        self.node.p2p_get_peer_count().await.map_err(RpcError::RpcError)
    }

    pub async fn connected_peers(&self) -> WRpcResult<Vec<ConnectedPeer>, N> {
        self.node.p2p_get_connected_peers().await.map_err(RpcError::RpcError)
    }

    pub async fn reserved_peers(&self) -> WRpcResult<Vec<SocketAddress>, N> {
        self.node.p2p_get_reserved_nodes().await.map_err(RpcError::RpcError)
    }

    pub async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> WRpcResult<(), N> {
        self.node.p2p_add_reserved_node(address).await.map_err(RpcError::RpcError)
    }

    pub async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> WRpcResult<(), N> {
        self.node.p2p_remove_reserved_node(address).await.map_err(RpcError::RpcError)
    }

    pub async fn submit_block(&self, block: HexEncoded<Block>) -> WRpcResult<(), N> {
        self.node.submit_block(block.take()).await.map_err(RpcError::RpcError)
    }

    pub async fn chainstate_info(&self) -> WRpcResult<ChainInfo, N> {
        self.node.chainstate_info().await.map_err(RpcError::RpcError)
    }

    pub async fn node_best_block_id(&self) -> WRpcResult<Id<GenBlock>, N> {
        self.node.get_best_block_id().await.map_err(RpcError::RpcError)
    }

    pub async fn node_best_block_height(&self) -> WRpcResult<BlockHeight, N> {
        self.node.get_best_block_height().await.map_err(RpcError::RpcError)
    }

    pub async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> WRpcResult<Option<Id<GenBlock>>, N> {
        self.node.get_block_id_at_height(block_height).await.map_err(RpcError::RpcError)
    }

    pub async fn get_node_block(&self, block_id: Id<Block>) -> WRpcResult<Option<Block>, N> {
        self.node.get_block(block_id).await.map_err(RpcError::RpcError)
    }

    pub async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> WRpcResult<Vec<(BlockHeight, Id<GenBlock>)>, N> {
        self.node
            .get_block_ids_as_checkpoints(start_height, end_height, step)
            .await
            .map_err(RpcError::RpcError)
    }
}

pub async fn start<N: NodeInterface + Clone + Send + Sync + 'static + Debug>(
    wallet_handle: WalletHandle<N>,
    node_rpc: N,
    config: WalletRpcConfig,
    chain_config: Arc<ChainConfig>,
    cold_wallet: bool,
) -> anyhow::Result<rpc::Rpc> {
    let WalletRpcConfig {
        bind_addr,
        auth_credentials,
    } = config;

    let wallet_rpc = WalletRpc::new(wallet_handle, node_rpc, chain_config);
    let builder = rpc::Builder::new(bind_addr, auth_credentials)
        .with_method_list("list_methods")
        .register(ColdWalletRpcServer::into_rpc(wallet_rpc.clone()));

    if !cold_wallet {
        builder
            .register(WalletRpcServer::into_rpc(wallet_rpc.clone()))
            .register(WalletEventsRpcServer::into_rpc(wallet_rpc))
    } else {
        builder
    }
    .build()
    .await
}
