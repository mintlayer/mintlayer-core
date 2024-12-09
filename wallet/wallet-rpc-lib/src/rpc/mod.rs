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

use chainstate::{
    rpc::RpcOutputValueIn, tx_verifier::check_transaction, ChainInfo, TokenIssuanceError,
};
use crypto::{
    key::{hdkd::u31::U31, PrivateKey, PublicKey},
    vrf::VRFPublicKey,
};
use mempool::tx_accumulator::PackingStrategy;
use mempool_types::tx_options::TxOptionsOverrides;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use serialization::{hex_encoded::HexEncoded, Decode, DecodeAll};
use types::{
    AccountExtendedPublicKey, NewOrderTransaction, NewSubmittedTransaction, NewTokenTransaction,
    RpcHashedTimelockContract, RpcNewTransaction, RpcPreparedTransaction,
};
use utils::{ensure, shallow_clone::ShallowClone};
use utils_networking::IpOrSocketAddress;
use wallet::{
    account::{transaction_list::TransactionList, PoolData, TransactionToSign, TxInfo},
    WalletError,
};

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        output_value::OutputValue,
        signature::inputsig::arbitrary_message::{
            produce_message_challenge, ArbitraryMessageSignature,
        },
        tokens::{IsTokenFreezable, IsTokenUnfreezable, Metadata, TokenId, TokenTotalSupply},
        Block, ChainConfig, DelegationId, Destination, GenBlock, OrderId, PoolId,
        SignedTransaction, SignedTransactionIntent, Transaction, TxOutput, UtxoOutPoint,
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
        Balances, BlockInfo, CreatedBlockInfo, CreatedWallet, GenericTokenTransfer,
        InspectTransaction, NewTransaction, OpenedWallet, SeedWithPassPhrase, SweepFromAddresses,
        TransactionToInspect, WalletCreationOptions, WalletInfo, WalletTypeArgs,
    },
    ConnectedPeer, ControllerConfig, ControllerError, NodeInterface, UtxoState, UtxoStates,
    UtxoType, UtxoTypes, DEFAULT_ACCOUNT_INDEX,
};
use wallet_types::{
    account_info::StandaloneAddressDetails,
    partially_signed_transaction::PartiallySignedTransaction, scan_blockchain::ScanBlockchain,
    signature_status::SignatureStatus, wallet_tx::TxData, with_locked::WithLocked, Currency,
    SignedTxWithFees,
};

use crate::{WalletHandle, WalletRpcConfig};

#[cfg(feature = "trezor")]
use wallet_types::wallet_type::WalletType;

pub use self::types::RpcError;
use self::types::{
    AddressInfo, AddressWithUsageInfo, DelegationInfo, HardwareWalletType, LegacyVrfPublicKeyInfo,
    NewAccountInfo, PoolInfo, PublicKeyInfo, RpcAddress, RpcAmountIn, RpcHexString,
    RpcStandaloneAddress, RpcStandaloneAddressDetails, RpcStandaloneAddresses,
    RpcStandalonePrivateKeyAddress, RpcUtxoOutpoint, StakingStatus, StandaloneAddressWithDetails,
    VrfPublicKeyInfo,
};

#[derive(Clone)]
pub struct WalletRpc<N: Clone> {
    wallet: WalletHandle<N>,
    node: N,
    chain_config: Arc<ChainConfig>,
}

type WRpcResult<T, N> = Result<T, RpcError<N>>;

impl<N> WalletRpc<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
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

    pub fn shutdown(&self) -> WRpcResult<(), N> {
        self.wallet.shallow_clone().stop().map_err(RpcError::SubmitError)
    }

    pub async fn create_wallet(
        &self,
        path: PathBuf,
        args: WalletTypeArgs,
        options: WalletCreationOptions,
    ) -> WRpcResult<CreatedWallet, N> {
        self.wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move { wallet_manager.create_wallet(path, args, options).await })
            })
            .await?
    }

    pub async fn open_wallet(
        &self,
        wallet_path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: bool,
        scan_blockchain: ScanBlockchain,
        open_as_hw_wallet: Option<HardwareWalletType>,
    ) -> WRpcResult<OpenedWallet, N> {
        let (open_as_wallet_type, device_id) =
            open_as_hw_wallet.map_or((self.node.is_cold_wallet_node().await.into(), None), |hw| {
                match hw {
                    #[cfg(feature = "trezor")]
                    HardwareWalletType::Trezor { device_id } => (WalletType::Trezor, device_id),
                }
            });
        Ok(self
            .wallet
            .manage_async(move |wallet_manager| {
                Box::pin(async move {
                    wallet_manager
                        .open_wallet(
                            wallet_path,
                            password,
                            force_migrate_wallet_type,
                            scan_blockchain,
                            open_as_wallet_type,
                            device_id,
                        )
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

    pub async fn find_timestamps_for_staking(
        &self,
        pool_id: RpcAddress<PoolId>,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> WRpcResult<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, N> {
        let pool_id =
            pool_id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidPoolId)?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.find_timestamps_for_staking(
                        pool_id,
                        min_height,
                        max_height,
                        seconds_to_check_for_height,
                        check_all_timestamps_between_blocks,
                    )
                    .await
                })
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

    pub async fn standalone_address_label_rename(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        label: Option<String>,
    ) -> WRpcResult<(), N> {
        let dest = address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .standalone_address_label_rename(dest, label)
                })
            })
            .await??;
        Ok(())
    }

    pub async fn add_standalone_watch_only_address(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        label: Option<String>,
        no_rescan: bool,
    ) -> WRpcResult<(), N> {
        let dest = address
            .decode_object(&self.chain_config)
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
                    let res = w
                        .synced_controller(account_index, config)
                        .await?
                        .add_standalone_address(pkh, label);

                    if !no_rescan {
                        w.reset_wallet_to_genesis()?;
                    }

                    res
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
        no_rescan: bool,
    ) -> WRpcResult<(), N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let res = w
                        .synced_controller(account_index, config)
                        .await?
                        .add_standalone_private_key(private_key, label);

                    if !no_rescan {
                        w.reset_wallet_to_genesis()?;
                    }

                    res
                })
            })
            .await??;
        Ok(())
    }

    pub async fn add_standalone_multisig(
        &self,
        account_index: U31,
        min_required_signatures: u8,
        public_keys: Vec<RpcAddress<Destination>>,
        label: Option<String>,
        no_rescan: bool,
    ) -> WRpcResult<String, N> {
        let config = ControllerConfig {
            in_top_x_mb: 5,
            broadcast_to_mempool: true,
        }; // irrelevant for issuing addresses
        let min_required_signatures =
            NonZeroU8::new(min_required_signatures).ok_or(RpcError::InvalidMultisigMinSignature)?;

        let public_keys = public_keys
            .into_iter()
            .enumerate()
            .map(|(idx, addr)| {
                addr.decode_object(&self.chain_config)
                    .map_err(|_| RpcError::MultisigNotPublicKey(idx))
                    .and_then(|dest| match dest {
                        Destination::PublicKey(pk) => Ok(pk),
                        Destination::PublicKeyHash(_)
                        | Destination::AnyoneCanSpend
                        | Destination::ScriptHash(_)
                        | Destination::ClassicMultisig(_) => {
                            Err(RpcError::MultisigNotPublicKey(idx))
                        }
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
                    let res = w
                        .synced_controller(account_index, config)
                        .await?
                        .add_standalone_multisig(challenge, label);

                    if !no_rescan {
                        w.reset_wallet_to_genesis()?;
                    }

                    res
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

    pub async fn get_account_extended_public_key(
        &self,
        account_index: U31,
    ) -> WRpcResult<AccountExtendedPublicKey, N> {
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.readonly_controller(account_index).account_extended_public_key().cloned()
                })
            })
            .await?
            .map(AccountExtendedPublicKey::new)
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

    pub async fn get_transaction_list(
        &self,
        account_index: U31,
        skip: usize,
        count: usize,
    ) -> WRpcResult<TransactionList, N> {
        let txs = self
            .wallet
            .call(move |controller| {
                controller.readonly_controller(account_index).get_transaction_list(skip, count)
            })
            .await??;
        Ok(txs)
    }

    pub async fn get_issued_addresses(
        &self,
        account_index: U31,
        include_change_addresses: bool,
    ) -> WRpcResult<Vec<AddressWithUsageInfo>, N> {
        let addresses: Vec<_> = self
            .wallet
            .call(move |controller| {
                controller
                    .readonly_controller(account_index)
                    .get_addresses_with_usage(include_change_addresses)
            })
            .await??;
        let result = addresses
            .into_iter()
            .map(|info| {
                AddressWithUsageInfo::new(
                    info.child_number,
                    info.purpose,
                    info.address,
                    info.used,
                    info.coins,
                    &self.chain_config,
                )
            })
            .collect();
        Ok(result)
    }

    pub async fn get_standalone_addresses(
        &self,
        account_index: U31,
    ) -> WRpcResult<RpcStandaloneAddresses, N> {
        let addresses = self
            .wallet
            .call(move |controller| {
                controller.readonly_controller(account_index).get_standalone_addresses()
            })
            .await??;
        let result = RpcStandaloneAddresses {
            watch_only_addresses: addresses
                .watch_only_addresses
                .into_iter()
                .map(|(dest, info)| RpcStandaloneAddress::new(dest, info.label, &self.chain_config))
                .collect(),
            multisig_addresses: addresses
                .multisig_addresses
                .into_iter()
                .map(|(dest, info)| RpcStandaloneAddress::new(dest, info.label, &self.chain_config))
                .collect(),
            private_key_addresses: addresses
                .private_keys
                .into_iter()
                .map(|(pk, label)| {
                    let pkh = (&pk).into();
                    RpcStandalonePrivateKeyAddress::new(pk, pkh, label, &self.chain_config)
                })
                .collect(),
        };
        Ok(result)
    }

    pub async fn get_standalone_address_details(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
    ) -> WRpcResult<StandaloneAddressWithDetails, N> {
        let address = address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let chain_config = self.chain_config.clone();
        let result = self
            .wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.readonly_controller(account_index)
                        .get_standalone_address_details(address)
                        .await
                        .map(|info| {
                            let address = Address::new(&chain_config, info.address)
                                .expect("Addressable")
                                .into_string();
                            match info.details {
                                StandaloneAddressDetails::WatchOnly(watch_only) => {
                                    StandaloneAddressWithDetails {
                                        address,
                                        label: watch_only.label.clone(),
                                        balances: info.balances,
                                        details: RpcStandaloneAddressDetails::WatchOnly,
                                    }
                                }
                                StandaloneAddressDetails::PrivateKey(label) => {
                                    StandaloneAddressWithDetails {
                                        address,
                                        label: label.clone(),
                                        balances: info.balances,
                                        details: RpcStandaloneAddressDetails::FromPrivateKey,
                                    }
                                }
                                StandaloneAddressDetails::Multisig(multisig) => {
                                    StandaloneAddressWithDetails {
                                        address,
                                        label: multisig.label.clone(),
                                        balances: info.balances,
                                        details: RpcStandaloneAddressDetails::Multisig {
                                            min_required_signatures: multisig
                                                .challenge
                                                .min_required_signatures(),
                                            public_keys: multisig
                                                .challenge
                                                .public_keys()
                                                .iter()
                                                .map(|pk| {
                                                    Address::new(
                                                        &chain_config,
                                                        Destination::PublicKey(pk.clone()),
                                                    )
                                                    .expect("Addressable")
                                                    .into()
                                                })
                                                .collect(),
                                        },
                                    }
                                }
                            }
                        })
                })
            })
            .await??;
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
    ) -> WRpcResult<NewSubmittedTransaction, N> {
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

        Ok(NewSubmittedTransaction { tx_id })
    }

    pub async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: RpcHexString,
        config: ControllerConfig,
    ) -> WRpcResult<
        (
            PartiallySignedTransaction,
            Vec<SignatureStatus>,
            Vec<SignatureStatus>,
        ),
        N,
    > {
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
                        .await
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
                        .sign_challenge(&challenge, &destination)
                        .await
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
        all: bool,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
        ensure!(
            all && from_addresses.is_empty() || !all && !from_addresses.is_empty(),
            RpcError::<N>::InvalidSweepParameters
        );

        let destination_address = destination_address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let from_addresses = match all {
            true => SweepFromAddresses::All,
            false => SweepFromAddresses::SpecificAddresses(
                from_addresses
                    .into_iter()
                    .map(|a| {
                        a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress)
                    })
                    .collect::<Result<BTreeSet<Destination>, _>>()?,
            ),
        };

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .sweep_addresses(destination_address, from_addresses)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<RpcNewTransaction, N> {
        let delegation_id = delegation_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidDelegationId)?;
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
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn create_transaction_for_sending_tokens_with_intent(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        intent: String,
        config: ControllerConfig,
    ) -> WRpcResult<(SignedTxWithFees, SignedTransactionIntent), N> {
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
                        .create_transaction_for_sending_tokens_to_address_with_intent(
                            token_info, address, amount, intent,
                        )
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
    }

    pub async fn make_tx_to_send_tokens_from_multisig_address(
        &self,
        account_index: U31,
        from_rpc_address: RpcAddress<Destination>,
        fee_change_rpc_address: Option<RpcAddress<Destination>>,
        outputs: Vec<GenericTokenTransfer>,
        config: ControllerConfig,
    ) -> WRpcResult<
        (
            PartiallySignedTransaction,
            Vec<SignatureStatus>,
            /*fees:*/ Balances,
        ),
        N,
    > {
        let from_address = from_rpc_address
            .clone()
            .into_address(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddressWithAddr(from_rpc_address.into_string()))?;

        ensure!(
            matches!(from_address.as_object(), Destination::ClassicMultisig(_)),
            RpcError::NotMultisigAddress(from_address.as_str().to_owned())
        );

        ensure!(!outputs.is_empty(), RpcError::NoOutputsSpecified);

        let outputs_by_token_id = {
            let mut result = BTreeMap::<_, Vec<_>>::new();

            for output in outputs {
                let (token_id, currency_transfer) = output.into_currency_transfer();
                result.entry(token_id).or_default().push(currency_transfer);
            }

            result
        };

        let inputs = self
            .get_multisig_utxos(
                account_index,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                UtxoState::Confirmed | UtxoState::InMempool,
                WithLocked::Unlocked,
            )
            .await?;

        let inputs = inputs
            .into_iter()
            .filter(|(_, txo)| {
                let (val, dest) = match txo {
                    TxOutput::Transfer(val, dest) | TxOutput::LockThenTransfer(val, dest, _) => {
                        (val, dest)
                    }
                    TxOutput::CreateDelegationId(_, _)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateStakePool(_, _)
                    | TxOutput::Htlc(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::Burn(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::CreateOrder(_) => return false,
                };

                let src_token_id = match val {
                    OutputValue::Coin(_) | OutputValue::TokenV0(_) => return false,
                    OutputValue::TokenV1(token_id, _) => token_id,
                };

                outputs_by_token_id.contains_key(src_token_id) && dest == from_address.as_object()
            })
            .collect::<Vec<_>>();

        ensure!(
            !inputs.is_empty(),
            RpcError::NoUtxosForMultisigAddressForTokens(
                outputs_by_token_id.keys().copied().collect()
            )
        );

        let change_addresses = {
            let mut change_addresses = BTreeMap::new();

            if let Some(fee_change_rpc_address) = fee_change_rpc_address {
                let fee_change_addr =
                    fee_change_rpc_address.clone().into_address(&self.chain_config).map_err(
                        |_| RpcError::InvalidAddressWithAddr(fee_change_rpc_address.into_string()),
                    )?;

                change_addresses.insert(Currency::Coin, fee_change_addr);
            }

            for token_id in outputs_by_token_id.keys() {
                change_addresses.insert(Currency::Token(*token_id), from_address.clone());
            }

            change_addresses
        };

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    let mut synced_controller =
                        controller.synced_controller(account_index, config).await?;

                    let (tx, fees) = synced_controller
                        .make_unsigned_tx_to_send_tokens_to_addresses(
                            inputs,
                            outputs_by_token_id,
                            change_addresses,
                        )
                        .await
                        .map_err(RpcError::Controller)?;

                    let (tx, _, cur_signatures) = synced_controller
                        .sign_raw_transaction(TransactionToSign::Partial(tx))
                        .await
                        .map_err(RpcError::Controller)?;

                    Ok::<_, RpcError<N>>((tx, cur_signatures, fees))
                })
            })
            .await?
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: RpcAmountIn,
        cost_per_block: RpcAmountIn,
        margin_ratio_per_thousand: String,
        decommission_address: RpcAddress<Destination>,
        staker_address: Option<RpcAddress<Destination>>,
        vrf_public_key: Option<RpcAddress<VRFPublicKey>>,
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

        let staker_destination = staker_address
            .map(|staker| {
                staker.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress)
            })
            .transpose()?;

        let vrf_public_key = vrf_public_key
            .map(|vrf_public_key| {
                vrf_public_key
                    .decode_object(&self.chain_config)
                    .map_err(|_| RpcError::InvalidAddress)
            })
            .transpose()?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_stake_pool(
                            amount,
                            decommission_destination,
                            margin_ratio_per_thousand,
                            cost_per_block,
                            staker_destination,
                            vrf_public_key,
                        )
                        .await
                        .map_err(RpcError::Controller)
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
    ) -> WRpcResult<(NewTransaction, RpcAddress<DelegationId>), N> {
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
            .map(|(tx, delegation_id)| {
                (
                    tx,
                    RpcAddress::new(&self.chain_config, delegation_id)
                        .expect("addressable delegation id"),
                )
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

    pub async fn create_htlc_transaction(
        &self,
        account_index: U31,
        amount: RpcAmountIn,
        token_id: Option<RpcAddress<TokenId>>,
        htlc: RpcHashedTimelockContract,
        config: ControllerConfig,
    ) -> WRpcResult<RpcPreparedTransaction, N> {
        let secret_hash = HtlcSecretHash::decode_all(&mut htlc.secret_hash.as_bytes())
            .map_err(|_| RpcError::InvalidHtlcSecretHash)?;

        let spend_key = htlc
            .spend_address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let refund_key = htlc
            .refund_address
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        let htlc = HashedTimelockContract {
            secret_hash,
            spend_key,
            refund_timelock: htlc.refund_timelock,
            refund_key,
        };

        let token_id = token_id
            .map(|id| id.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidTokenId))
            .transpose()?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_htlc_tx(amount, token_id, htlc)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcPreparedTransaction::new)
                })
            })
            .await?
    }

    pub async fn create_order(
        &self,
        account_index: U31,
        ask: RpcOutputValueIn,
        give: RpcOutputValueIn,
        conclude_address: RpcAddress<Destination>,
        config: ControllerConfig,
    ) -> WRpcResult<NewOrderTransaction, N> {
        let conclude_dest = conclude_address
            .into_address(&self.chain_config)
            .map_err(|_| RpcError::InvalidAddress)?;

        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .create_order(ask, give, conclude_dest)
                        .await
                        .map_err(RpcError::Controller)
                })
            })
            .await?
            .map(|(tx, order_id)| {
                NewOrderTransaction::new(
                    tx,
                    RpcAddress::new(&self.chain_config, order_id).expect("addressable order id"),
                )
            })
    }

    pub async fn conclude_order(
        &self,
        account_index: U31,
        order_id: RpcAddress<OrderId>,
        output_address: Option<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
        let order_id = order_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        let output_address = output_address
            .map(|a| a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress))
            .transpose()?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .conclude_order(order_id, output_address)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn fill_order(
        &self,
        account_index: U31,
        order_id: RpcAddress<OrderId>,
        fill_amount_in_ask_currency: RpcAmountIn,
        output_address: Option<RpcAddress<Destination>>,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
        let order_id = order_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        let output_address = output_address
            .map(|a| a.decode_object(&self.chain_config).map_err(|_| RpcError::InvalidAddress))
            .transpose()?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .fill_order(order_id, fill_amount_in_ask_currency, output_address)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn freeze_order(
        &self,
        account_index: U31,
        order_id: RpcAddress<OrderId>,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
        let order_id = order_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.synced_controller(account_index, config)
                        .await?
                        .freeze_order(order_id)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn compose_transaction(
        &self,
        inputs: Vec<RpcUtxoOutpoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<RpcHexString>>>,
        only_transaction: bool,
    ) -> WRpcResult<(TransactionToSign, Balances), N> {
        ensure!(!inputs.is_empty(), RpcError::ComposeTransactionEmptyInputs);
        let inputs = inputs.into_iter().map(|o| o.into_outpoint()).collect();

        let htlc_secrets = htlc_secrets
            .map(|htlc_secrets| {
                htlc_secrets
                    .into_iter()
                    .map(|s| {
                        s.map(|s| -> Result<HtlcSecret, RpcError<N>> {
                            Ok(HtlcSecret::new(
                                s.into_bytes()
                                    .try_into()
                                    .map_err(|_| RpcError::InvalidHtlcSecret)?,
                            ))
                        })
                        .transpose()
                    })
                    .collect()
            })
            .transpose()?;

        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    w.compose_transaction(inputs, outputs, htlc_secrets, only_transaction).await
                })
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
    ) -> WRpcResult<RpcNewTransaction, N> {
        self.wallet
            .call_async(move |controller| {
                Box::pin(async move {
                    controller
                        .synced_controller(account_index, config)
                        .await?
                        .deposit_data(data)
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<NewTokenTransaction, N> {
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
            .map(|(tx, token_id)| {
                NewTokenTransaction::new(
                    tx,
                    RpcAddress::new(&self.chain_config, token_id)
                        .expect("Encoding token id should never fail"),
                )
            })
    }

    pub async fn issue_new_nft(
        &self,
        account_index: U31,
        address: RpcAddress<Destination>,
        metadata: Metadata,
        config: ControllerConfig,
    ) -> WRpcResult<NewTokenTransaction, N> {
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
            .map(|(tx, token_id)| {
                NewTokenTransaction::new(
                    tx,
                    RpcAddress::new(&self.chain_config, token_id)
                        .expect("Encoding token id should never fail"),
                )
            })
    }

    pub async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
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
    ) -> WRpcResult<RpcNewTransaction, N> {
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
                        .map(RpcNewTransaction::new)
                })
            })
            .await?
    }

    pub async fn change_token_metadata_uri(
        &self,
        account_index: U31,
        token_id: RpcAddress<TokenId>,
        metadata_uri: RpcHexString,
        config: ControllerConfig,
    ) -> WRpcResult<RpcNewTransaction, N> {
        let token_id = token_id
            .decode_object(&self.chain_config)
            .map_err(|_| RpcError::InvalidTokenId)?;
        self.wallet
            .call_async(move |w| {
                Box::pin(async move {
                    let token_info = w.get_token_info(token_id).await?;

                    w.synced_controller(account_index, config)
                        .await?
                        .change_token_metadata_uri(token_info, metadata_uri.into_bytes())
                        .await
                        .map_err(RpcError::Controller)
                        .map(RpcNewTransaction::new)
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
                    .map(|(delegation_id, pool_id, balance)| {
                        DelegationInfo::new(delegation_id, pool_id, balance, &self.chain_config)
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

    pub async fn undiscourage_address(&self, address: BannableAddress) -> WRpcResult<(), N> {
        self.node.p2p_undiscourage(address).await.map_err(RpcError::RpcError)
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

pub async fn start<N>(
    wallet_handle: WalletHandle<N>,
    node_rpc: N,
    config: WalletRpcConfig,
    chain_config: Arc<ChainConfig>,
    cold_wallet: bool,
) -> anyhow::Result<rpc::Rpc>
where
    N: NodeInterface + Clone + Send + Sync + 'static + Debug,
{
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
