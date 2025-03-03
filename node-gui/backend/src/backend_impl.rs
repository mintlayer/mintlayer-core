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

use std::{collections::BTreeMap, fmt::Debug, path::PathBuf, str::FromStr, sync::Arc};

use common::{
    address::{Address, RpcAddress},
    chain::{ChainConfig, GenBlock, SignedTransaction},
    primitives::{per_thousand::PerThousand, BlockHeight, Id},
};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};
use futures::{stream::FuturesOrdered, TryStreamExt};
use logging::log;
use node_comm::rpc_client::ColdWalletClient;
use node_lib::node_controller::NodeController;
use serialization::hex_encoded::HexEncoded;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use wallet::{account::transaction_list::TransactionList, wallet::Error, WalletError};
use wallet_cli_commands::{
    get_repl_command, parse_input, CommandHandler, ConsoleCommand, ManageableWalletCommand,
    WalletCommand,
};
use wallet_controller::{
    make_cold_wallet_rpc_client,
    types::{Balances, WalletCreationOptions, WalletTypeArgs},
    ControllerConfig, NodeInterface, UtxoState, WalletHandlesClient,
};
use wallet_rpc_client::handles_client::WalletRpcHandlesClient;
use wallet_rpc_lib::{types::HardwareWalletType, EventStream, WalletRpc, WalletService};
use wallet_types::{
    scan_blockchain::ScanBlockchain, wallet_type::WalletType, with_locked::WithLocked,
};

use super::{
    account_id::AccountId,
    chainstate_event_handler::ChainstateEventHandler,
    error::BackendError,
    messages::{
        AccountInfo, AddressInfo, BackendEvent, BackendRequest, CreateDelegationRequest,
        DecommissionPoolRequest, DelegateStakingRequest, EncryptionAction, EncryptionState,
        SendDelegateToAddressRequest, SendRequest, SignedTransactionWrapper, StakeRequest,
        TransactionInfo, WalletId, WalletInfo,
    },
    p2p_event_handler::P2pEventHandler,
    parse_address, parse_coin_amount,
    wallet_events::GuiWalletEvents,
    ImportOrCreate,
};

const TRANSACTION_LIST_PAGE_COUNT: usize = 10;
/// In which top N MB should we aim for our transactions to be in the mempool
/// e.g. for 5, we aim to be in the top 5 MB of transactions based on paid fees
/// This is to avoid getting trimmed off the lower end if the mempool runs out of memory
const IN_TOP_X_MB: usize = 5;

enum GuiHotColdController {
    Hot(
        WalletRpc<WalletHandlesClient>,
        CommandHandler<WalletRpcHandlesClient<WalletHandlesClient>>,
    ),
    Cold(
        WalletRpc<ColdWalletClient>,
        CommandHandler<WalletRpcHandlesClient<ColdWalletClient>>,
    ),
}

struct WalletData {
    controller: GuiHotColdController,
    best_block: (Id<GenBlock>, BlockHeight),
    accounts: BTreeMap<AccountId, AccountData>,
    updated: bool,
}

impl WalletData {
    fn hot_wallet(&mut self) -> Option<&mut WalletRpc<WalletHandlesClient>> {
        match &mut self.controller {
            GuiHotColdController::Hot(w, _) => Some(w),
            GuiHotColdController::Cold(_, _) => None,
        }
    }

    async fn shutdown(mut self) {
        match &mut self.controller {
            GuiHotColdController::Hot(w, _) => {
                w.close_wallet().await.expect("should close the wallet");
                w.shutdown().expect("should close the wallet");
            }
            GuiHotColdController::Cold(w, _) => {
                w.close_wallet().await.expect("should close the wallet");
                w.shutdown().expect("should close the wallet");
            }
        }
    }
}

enum ColdHotNodeController {
    Cold,
    Hot(NodeController),
}

impl ColdHotNodeController {
    fn shutdown(self) {
        match self {
            Self::Hot(controller) => {
                controller.shutdown_trigger.initiate();
            }
            Self::Cold => {}
        }
    }

    fn is_cold(&self) -> bool {
        match self {
            Self::Hot(_) => false,
            Self::Cold => true,
        }
    }
}

struct AccountData {
    /// How many transactions the user has seen and scrolled (can be 0, 10, 20, etc).
    /// The variable is stored here so that the backend can send transaction list updates automatically.
    transaction_list_skip: usize,

    /// If set, pool balances and delegations should be updated in the UI.
    /// The flag is necessary because the pool balances load requires RPC call and may fail.
    update_pool_balance_and_delegations: bool,
}

pub struct Backend {
    chain_config: Arc<ChainConfig>,

    /// The bounded sender is used so that the UI is not overloaded with messages.
    /// With an unbounded sender, high latency was experienced when wallet scan was enabled.
    event_tx: UnboundedSender<BackendEvent>,
    /// Low priority event_tx for sending wallet updates when new blocks are scanned
    /// without this the queue can get filled up with updates when the wallet is far behind
    /// and user events interacting with the wallet can start lagging
    low_priority_event_tx: UnboundedSender<BackendEvent>,

    wallet_updated_tx: UnboundedSender<WalletId>,

    controller: ColdHotNodeController,

    manager_join_handle: JoinHandle<()>,

    wallets: BTreeMap<WalletId, WalletData>,
}

impl Backend {
    pub fn new_hot(
        chain_config: Arc<ChainConfig>,
        event_tx: UnboundedSender<BackendEvent>,
        low_priority_event_tx: UnboundedSender<BackendEvent>,
        wallet_updated_tx: UnboundedSender<WalletId>,
        controller: NodeController,
        manager_join_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            chain_config,
            event_tx,
            low_priority_event_tx,
            wallet_updated_tx,
            controller: ColdHotNodeController::Hot(controller),
            manager_join_handle,
            wallets: BTreeMap::new(),
        }
    }

    pub fn new_cold(
        chain_config: Arc<ChainConfig>,
        event_tx: UnboundedSender<BackendEvent>,
        low_priority_event_tx: UnboundedSender<BackendEvent>,
        wallet_updated_tx: UnboundedSender<WalletId>,
        manager_join_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            controller: ColdHotNodeController::Cold,
            chain_config,
            event_tx,
            low_priority_event_tx,
            wallet_updated_tx,
            manager_join_handle,
            wallets: BTreeMap::new(),
        }
    }

    fn get_account_data(_account_index: U31) -> AccountData {
        AccountData {
            transaction_list_skip: 0,
            update_pool_balance_and_delegations: true,
        }
    }

    async fn get_account_info<T>(
        controller: &WalletRpc<T>,
        account_index: U31,
    ) -> Result<(AccountId, AccountInfo), BackendError>
    where
        T: NodeInterface + Clone + Send + Sync + Debug + 'static,
    {
        let name = controller
            .wallet_info()
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?
            .account_names
            .into_iter()
            .nth(account_index.into_u32() as usize)
            .flatten();

        let addresses = controller
            .get_issued_addresses(account_index)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?
            .into_iter()
            .map(|info| {
                Ok((
                    ChildNumber::from_str(&info.index)
                        .map_err(|e| BackendError::InvalidAddressIndex(e.to_string()))?
                        .get_index()
                        .into_u32(),
                    info.address.into_string(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let transaction_list = controller
            .get_transaction_list(account_index, 0, TRANSACTION_LIST_PAGE_COUNT)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        let balance = get_account_balance(controller, account_index).await?;

        Ok((
            AccountId::new(account_index),
            AccountInfo {
                name,
                addresses,
                staking_enabled: false,
                balance,
                staking_balance: Default::default(),
                delegations_balance: Default::default(),
                transaction_list,
            },
        ))
    }

    async fn add_create_wallet(
        &mut self,
        file_path: PathBuf,
        wallet_args: WalletTypeArgs,
        wallet_type: WalletType,
        import: ImportOrCreate,
    ) -> Result<WalletInfo, BackendError> {
        let wallet_id = WalletId::new();
        let wallet_events = GuiWalletEvents::new(wallet_id, self.wallet_updated_tx.clone());

        let (wallet_data, accounts_info, best_block) = match (wallet_type, &self.controller) {
            (WalletType::Hot, ColdHotNodeController::Hot(controller)) => {
                let handles_client = WalletHandlesClient::new(
                    controller.chainstate.clone(),
                    controller.mempool.clone(),
                    controller.block_prod.clone(),
                    controller.p2p.clone(),
                )
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?;

                let (wallet_rpc, command_handler, best_block, accounts_info, accounts_data) = self
                    .create_wallet(
                        handles_client,
                        file_path.clone(),
                        wallet_args,
                        import,
                        wallet_events,
                    )
                    .await?;

                let wallet_data = WalletData {
                    controller: GuiHotColdController::Hot(wallet_rpc, command_handler),
                    accounts: accounts_data,
                    best_block,
                    updated: false,
                };

                (wallet_data, accounts_info, best_block)
            }
            (WalletType::Cold, _) => {
                let client = make_cold_wallet_rpc_client(Arc::clone(&self.chain_config));

                let (wallet_rpc, command_handler, best_block, accounts_info, accounts_data) = self
                    .create_wallet(
                        client,
                        file_path.clone(),
                        wallet_args,
                        import,
                        wallet_events,
                    )
                    .await?;

                let wallet_data = WalletData {
                    controller: GuiHotColdController::Cold(wallet_rpc, command_handler),
                    accounts: accounts_data,
                    best_block,
                    updated: false,
                };

                (wallet_data, accounts_info, best_block)
            }
            #[cfg(feature = "trezor")]
            (WalletType::Trezor, ColdHotNodeController::Hot(controller)) => {
                let handles_client = WalletHandlesClient::new(
                    controller.chainstate.clone(),
                    controller.mempool.clone(),
                    controller.block_prod.clone(),
                    controller.p2p.clone(),
                )
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?;

                let (wallet_rpc, command_handler, best_block, accounts_info, accounts_data) = self
                    .create_wallet(
                        handles_client,
                        file_path.clone(),
                        wallet_args,
                        import,
                        wallet_events,
                    )
                    .await?;

                let wallet_data = WalletData {
                    controller: GuiHotColdController::Hot(wallet_rpc, command_handler),
                    accounts: accounts_data,
                    best_block,
                    updated: false,
                };

                (wallet_data, accounts_info, best_block)
            }
            #[cfg(feature = "trezor")]
            (WalletType::Trezor, ColdHotNodeController::Cold) => {
                return Err(BackendError::ColdTrezorNotSupported)
            }
            (WalletType::Hot, ColdHotNodeController::Cold) => {
                return Err(BackendError::HotNotSupported)
            }
        };

        let encryption = EncryptionState::Disabled;

        let wallet_info = WalletInfo {
            wallet_id,
            path: file_path,
            encryption,
            accounts: accounts_info,
            best_block,
            wallet_type,
        };

        self.wallets.insert(wallet_id, wallet_data);

        Ok(wallet_info)
    }

    async fn create_wallet<N>(
        &mut self,
        handles_client: N,
        file_path: PathBuf,
        wallet_args: WalletTypeArgs,
        import: ImportOrCreate,
        wallet_events: GuiWalletEvents,
    ) -> Result<
        (
            WalletRpc<N>,
            CommandHandler<WalletRpcHandlesClient<N>>,
            (Id<GenBlock>, BlockHeight),
            BTreeMap<AccountId, AccountInfo>,
            BTreeMap<AccountId, AccountData>,
        ),
        BackendError,
    >
    where
        N: NodeInterface + Clone + Debug + Send + Sync + 'static,
    {
        let wallet_service = WalletService::start(
            self.chain_config.clone(),
            None,
            false,
            vec![],
            handles_client,
        )
        .await
        .map_err(|err| BackendError::WalletError(err.to_string()))?;
        let wallet_handle = wallet_service.handle();
        let node_rpc = wallet_service.node_rpc().clone();
        let chain_config = wallet_service.chain_config().clone();
        let wallet_rpc = WalletRpc::new(wallet_handle, node_rpc.clone(), chain_config.clone());

        let options = WalletCreationOptions {
            overwrite_wallet_file: true,
            scan_blockchain: import.should_scan_blockchain(),
        };
        wallet_rpc
            .create_wallet(file_path, wallet_args, options)
            .await
            .map_err(|err| BackendError::WalletError(err.to_string()))?;
        tokio::spawn(forward_events(
            wallet_events,
            wallet_service
                .handle()
                .subscribe()
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?,
        ));
        let command_handler = CommandHandler::new(
            ControllerConfig {
                in_top_x_mb: IN_TOP_X_MB,
                broadcast_to_mempool: true,
            },
            WalletRpcHandlesClient::new(wallet_rpc.clone(), None),
            None,
        )
        .await;
        let best_block = wallet_rpc
            .best_block()
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;
        let best_block = (best_block.id, best_block.height);
        let account_indexes = wallet_rpc.wallet_info().await.expect("").account_names.len();
        let accounts_info: FuturesOrdered<_> = (0..account_indexes)
            .map(|account_index| {
                let account_index = U31::from_u32(account_index as u32).expect("valid num");
                Self::get_account_info(&wallet_rpc, account_index)
            })
            .collect();
        let accounts_info = accounts_info.try_collect().await?;
        let accounts_data = (0..account_indexes)
            .map(|account_index| {
                let account_index = U31::from_u32(account_index as u32).expect("valid num");
                (
                    AccountId::new(account_index),
                    Self::get_account_data(account_index),
                )
            })
            .collect();
        Ok((
            wallet_rpc,
            command_handler,
            best_block,
            accounts_info,
            accounts_data,
        ))
    }

    async fn add_open_wallet(
        &mut self,
        file_path: PathBuf,
        wallet_type: WalletType,
    ) -> Result<WalletInfo, BackendError> {
        let wallet_id = WalletId::new();
        let wallet_events = GuiWalletEvents::new(wallet_id, self.wallet_updated_tx.clone());

        let (wallet_data, accounts_info, best_block, encryption) =
            match (wallet_type, &self.controller) {
                (WalletType::Hot, ColdHotNodeController::Hot(controller)) => {
                    let handles_client = WalletHandlesClient::new(
                        controller.chainstate.clone(),
                        controller.mempool.clone(),
                        controller.block_prod.clone(),
                        controller.p2p.clone(),
                    )
                    .await
                    .map_err(|e| BackendError::WalletError(e.to_string()))?;

                    let (
                        wallet_rpc,
                        command_handler,
                        encryption_state,
                        best_block,
                        accounts_info,
                        accounts_data,
                    ) = self
                        .open_wallet(handles_client, file_path.clone(), wallet_events, None)
                        .await?;

                    let wallet_data = WalletData {
                        controller: GuiHotColdController::Hot(wallet_rpc, command_handler),
                        accounts: accounts_data,
                        best_block,
                        updated: false,
                    };

                    (wallet_data, accounts_info, best_block, encryption_state)
                }
                (WalletType::Cold, _) => {
                    let client = make_cold_wallet_rpc_client(Arc::clone(&self.chain_config));

                    let (
                        wallet_rpc,
                        command_handler,
                        encryption_state,
                        best_block,
                        accounts_info,
                        accounts_data,
                    ) = self.open_wallet(client, file_path.clone(), wallet_events, None).await?;

                    let wallet_data = WalletData {
                        controller: GuiHotColdController::Cold(wallet_rpc, command_handler),
                        accounts: accounts_data,
                        best_block,
                        updated: false,
                    };

                    (wallet_data, accounts_info, best_block, encryption_state)
                }
                #[cfg(feature = "trezor")]
                (WalletType::Trezor, ColdHotNodeController::Hot(controller)) => {
                    let handles_client = WalletHandlesClient::new(
                        controller.chainstate.clone(),
                        controller.mempool.clone(),
                        controller.block_prod.clone(),
                        controller.p2p.clone(),
                    )
                    .await
                    .map_err(|e| BackendError::WalletError(e.to_string()))?;

                    let (
                        wallet_rpc,
                        command_handler,
                        encryption_state,
                        best_block,
                        accounts_info,
                        accounts_data,
                    ) = self
                        .open_wallet(
                            handles_client,
                            file_path.clone(),
                            wallet_events,
                            Some(HardwareWalletType::Trezor),
                        )
                        .await?;

                    let wallet_data = WalletData {
                        controller: GuiHotColdController::Hot(wallet_rpc, command_handler),
                        accounts: accounts_data,
                        best_block,
                        updated: false,
                    };

                    (wallet_data, accounts_info, best_block, encryption_state)
                }
                #[cfg(feature = "trezor")]
                (WalletType::Trezor, ColdHotNodeController::Cold) => {
                    return Err(BackendError::ColdTrezorNotSupported)
                }
                (WalletType::Hot, ColdHotNodeController::Cold) => {
                    return Err(BackendError::HotNotSupported)
                }
            };

        let wallet_info = WalletInfo {
            wallet_id,
            path: file_path,
            encryption,
            accounts: accounts_info,
            best_block,
            wallet_type,
        };

        self.wallets.insert(wallet_id, wallet_data);

        Ok(wallet_info)
    }

    async fn open_wallet<N>(
        &mut self,
        handles_client: N,
        file_path: PathBuf,
        wallet_events: GuiWalletEvents,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> Result<
        (
            WalletRpc<N>,
            CommandHandler<WalletRpcHandlesClient<N>>,
            EncryptionState,
            (Id<GenBlock>, BlockHeight),
            BTreeMap<AccountId, AccountInfo>,
            BTreeMap<AccountId, AccountData>,
        ),
        BackendError,
    >
    where
        N: NodeInterface + Clone + Debug + Send + Sync + 'static,
    {
        let wallet_service = WalletService::start(
            self.chain_config.clone(),
            None,
            false,
            vec![],
            handles_client,
        )
        .await
        .map_err(|err| BackendError::WalletError(err.to_string()))?;
        let wallet_handle = wallet_service.handle();
        let node_rpc = wallet_service.node_rpc().clone();
        let chain_config = wallet_service.chain_config().clone();
        let wallet_rpc = WalletRpc::new(wallet_handle, node_rpc.clone(), chain_config.clone());
        wallet_rpc
            .open_wallet(
                file_path,
                None,
                false,
                ScanBlockchain::ScanNoWait,
                hardware_wallet,
            )
            .await
            .map_err(|err| BackendError::WalletError(err.to_string()))?;
        tokio::spawn(forward_events(
            wallet_events,
            wallet_service
                .handle()
                .subscribe()
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?,
        ));
        let command_handler = CommandHandler::new(
            ControllerConfig {
                in_top_x_mb: IN_TOP_X_MB,
                broadcast_to_mempool: true,
            },
            WalletRpcHandlesClient::new(wallet_rpc.clone(), None),
            None,
        )
        .await;
        let encryption_state = match wallet_rpc.remove_private_key_encryption().await {
            Ok(_) => EncryptionState::Disabled,
            Err(wallet_rpc_lib::RpcError::Controller(
                wallet_controller::ControllerError::WalletError(WalletError::DatabaseError(
                    Error::WalletLocked,
                )),
            )) => EncryptionState::EnabledLocked,
            Err(_) => EncryptionState::Disabled,
        };
        let best_block = wallet_rpc
            .best_block()
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;
        let best_block = (best_block.id, best_block.height);
        let account_indexes = wallet_rpc.wallet_info().await.expect("").account_names.len();
        let accounts_info: FuturesOrdered<_> = (0..account_indexes)
            .map(|account_index| {
                let account_index = U31::from_u32(account_index as u32).expect("valid num");
                Self::get_account_info(&wallet_rpc, account_index)
            })
            .collect();
        let accounts_info = accounts_info.try_collect().await?;
        let accounts_data = (0..account_indexes)
            .map(|account_index| {
                let account_index = U31::from_u32(account_index as u32).expect("valid num");
                (
                    AccountId::new(account_index),
                    Self::get_account_data(account_index),
                )
            })
            .collect();
        Ok((
            wallet_rpc,
            command_handler,
            encryption_state,
            best_block,
            accounts_info,
            accounts_data,
        ))
    }

    async fn update_encryption(
        &mut self,
        wallet_id: WalletId,
        action: EncryptionAction,
    ) -> Result<(WalletId, EncryptionState), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        match &mut wallet.controller {
            GuiHotColdController::Hot(w, _) => encrypt_action(action, w, wallet_id).await,
            GuiHotColdController::Cold(w, _) => encrypt_action(action, w, wallet_id).await,
        }
    }

    async fn new_account(
        &mut self,
        wallet_id: WalletId,
        name: String,
    ) -> Result<(WalletId, AccountId, AccountInfo), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let name = name.trim().to_owned();
        let name = (!name.is_empty()).then_some(name);

        let hot_wallet = wallet.hot_wallet().ok_or(BackendError::ColdWallet)?;
        let (account_index, _name) = hot_wallet
            .create_account(name)
            .await
            .map(|info| (U31::from_u32(info.account).expect("valid index"), info.name))
            .map_err(|err| BackendError::WalletError(err.to_string()))?;

        let (account_id, account_info) = Self::get_account_info(hot_wallet, account_index).await?;
        let account_data = Self::get_account_data(account_index);

        wallet.accounts.insert(account_id, account_data);

        Ok((wallet_id, account_id, account_info))
    }

    async fn new_address(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
    ) -> Result<AddressInfo, BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let (index, address) = match &mut wallet.controller {
            GuiHotColdController::Cold(w, _) => w
                .issue_address(account_id.account_index())
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))
                .map(|info| (info.index, info.address))?,
            GuiHotColdController::Hot(w, _) => w
                .issue_address(account_id.account_index())
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))
                .map(|info| (info.index, info.address))?,
        };

        AddressInfo::new(wallet_id, account_id, &index, address)
    }

    async fn toggle_staking(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
        enabled: bool,
    ) -> Result<(WalletId, AccountId, bool), BackendError> {
        if enabled {
            self.hot_wallet(wallet_id)?
                .start_staking(account_id.account_index())
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?;
        } else {
            self.hot_wallet(wallet_id)?
                .stop_staking(account_id.account_index())
                .await
                .map_err(|e| BackendError::WalletError(e.to_string()))?;
        }
        Ok((wallet_id, account_id, enabled))
    }

    fn hot_wallet(
        &mut self,
        wallet_id: WalletId,
    ) -> Result<&mut WalletRpc<WalletHandlesClient>, BackendError> {
        self.wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?
            .hot_wallet()
            .ok_or(BackendError::ColdWallet)
    }

    async fn send_amount(
        &mut self,
        send_request: SendRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let SendRequest {
            wallet_id,
            account_id,
            address,
            amount,
        } = send_request;

        let address = parse_address(&self.chain_config, &address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?;
        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidAmount(amount))?;

        // TODO: add support for utxo selection in the GUI
        let tx = self
            .hot_wallet(wallet_id)?
            .send_coins(
                account_id.account_index(),
                address.into(),
                amount.into(),
                vec![],
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn stake_amount(
        &mut self,
        stake_request: StakeRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let StakeRequest {
            wallet_id,
            account_id,
            pledge_amount: amount,
            mpt,
            cost_per_block,
            decommission_address,
        } = stake_request;

        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidPledgeAmount(amount))?;

        let cost_per_block = parse_coin_amount(&self.chain_config, &cost_per_block)
            .ok_or(BackendError::InvalidCostPerBlockAmount(cost_per_block))?;

        let mpt = PerThousand::from_decimal_str(&mpt)
            .map_err(|_| BackendError::InvalidMarginPerThousand(mpt))?;

        let decommission_key = parse_address(&self.chain_config, &decommission_address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?
            .into_object();

        let decommission_address =
            RpcAddress::new(&self.chain_config, decommission_key).expect("addressable");
        let tx = self
            .hot_wallet(wallet_id)?
            .create_stake_pool(
                account_id.account_index(),
                amount.into(),
                cost_per_block.into(),
                mpt.to_string(),
                decommission_address,
                None,
                None,
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn decommission_pool(
        &mut self,
        request: DecommissionPoolRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let DecommissionPoolRequest {
            wallet_id,
            account_id,
            pool_id,
            output_address,
        } = request;

        let tx = self
            .hot_wallet(wallet_id)?
            .decommission_stake_pool(
                account_id.account_index(),
                pool_id.into(),
                Some(output_address.into()),
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn create_delegation(
        &mut self,
        request: CreateDelegationRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let CreateDelegationRequest {
            wallet_id,
            account_id,
            pool_id,
            delegation_address,
        } = request;

        let (tx, _) = self
            .hot_wallet(wallet_id)?
            .create_delegation(
                account_id.account_index(),
                delegation_address.into(),
                pool_id.into(),
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn delegate_staking(
        &mut self,
        request: DelegateStakingRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let DelegateStakingRequest {
            wallet_id,
            account_id,
            delegation_id,
            delegation_amount,
        } = request;

        let delegation_amount = parse_coin_amount(&self.chain_config, &delegation_amount)
            .ok_or(BackendError::InvalidAmount(delegation_amount))?;

        let tx = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?
            .hot_wallet()
            .ok_or(BackendError::ColdWallet)?
            .delegate_staking(
                account_id.account_index(),
                delegation_amount.into(),
                RpcAddress::new(&self.chain_config, delegation_id).expect("addressable"),
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn send_delegation_to_address(
        &mut self,
        request: SendDelegateToAddressRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let SendDelegateToAddressRequest {
            wallet_id,
            account_id,
            address,
            amount,
            delegation_id,
        } = request;

        let address = parse_address(&self.chain_config, &address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?;

        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidAmount(amount))?;

        let delegation_id = Address::from_string(&self.chain_config, &delegation_id)
            .map_err(|e| BackendError::AddressError(e.to_string()))?;

        let tx = self
            .hot_wallet(wallet_id)?
            .withdraw_from_delegation(
                account_id.account_index(),
                address.into(),
                amount.into(),
                delegation_id.into(),
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                    // don't broadcast_to_mempool before confirmation dialog
                    broadcast_to_mempool: false,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo {
            wallet_id,
            tx: SignedTransactionWrapper::new(tx),
        })
    }

    async fn submit_transaction(
        &mut self,
        wallet_id: WalletId,
        tx: SignedTransaction,
    ) -> Result<WalletId, BackendError> {
        self.hot_wallet(wallet_id)?
            .submit_raw_transaction(HexEncoded::new(tx), false, Default::default())
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(wallet_id)
    }

    async fn load_transaction_list(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
        skip: usize,
    ) -> Result<TransactionList, BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;
        let account = wallet
            .accounts
            .get_mut(&account_id)
            .ok_or(BackendError::UnknownAccountIndex(wallet_id, account_id))?;
        account.transaction_list_skip = skip;
        wallet
            .hot_wallet()
            .ok_or(BackendError::ColdWallet)?
            .get_transaction_list(
                account_id.account_index(),
                skip,
                TRANSACTION_LIST_PAGE_COUNT,
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))
    }

    async fn process_request(&mut self, request: BackendRequest) {
        match request {
            BackendRequest::OpenWallet {
                file_path,
                wallet_type,
            } => {
                let open_res = self.add_open_wallet(file_path, wallet_type).await;
                Self::send_event(&self.event_tx, BackendEvent::OpenWallet(open_res));
            }
            BackendRequest::RecoverWallet {
                wallet_args,
                file_path,
                import,
                wallet_type,
            } => {
                let import_res =
                    self.add_create_wallet(file_path, wallet_args, wallet_type, import).await;
                Self::send_event(&self.event_tx, BackendEvent::ImportWallet(import_res));
            }
            BackendRequest::CloseWallet(wallet_id) => {
                if let Some(wallet) = self.wallets.remove(&wallet_id) {
                    wallet.shutdown().await;
                    Self::send_event(&self.event_tx, BackendEvent::CloseWallet(wallet_id));
                }
            }

            BackendRequest::UpdateEncryption { wallet_id, action } => {
                let res = self.update_encryption(wallet_id, action).await;
                Self::send_event(&self.event_tx, BackendEvent::UpdateEncryption(res));
            }

            BackendRequest::NewAccount { wallet_id, name } => {
                let res = self.new_account(wallet_id, name).await;
                Self::send_event(&self.event_tx, BackendEvent::NewAccount(res));
            }

            BackendRequest::NewAddress(wallet_id, account_id) => {
                let address_res = self.new_address(wallet_id, account_id).await;
                Self::send_event(&self.event_tx, BackendEvent::NewAddress(address_res));
            }
            BackendRequest::ToggleStaking(wallet_id, account_id, enabled) => {
                let toggle_res = self.toggle_staking(wallet_id, account_id, enabled).await;
                Self::send_event(&self.event_tx, BackendEvent::ToggleStaking(toggle_res));
            }
            BackendRequest::SendAmount(send_request) => {
                let send_res = self.send_amount(send_request).await;
                Self::send_event(&self.event_tx, BackendEvent::SendAmount(send_res));
            }
            BackendRequest::StakeAmount(stake_request) => {
                let stake_res = self.stake_amount(stake_request).await;
                Self::send_event(&self.event_tx, BackendEvent::StakeAmount(stake_res));
            }
            BackendRequest::DecommissionPool(decommission_request) => {
                let stake_res = self.decommission_pool(decommission_request).await;
                Self::send_event(&self.event_tx, BackendEvent::DecommissionPool(stake_res));
            }
            BackendRequest::CreateDelegation(request) => {
                let result = self.create_delegation(request).await;
                Self::send_event(&self.event_tx, BackendEvent::CreateDelegation(result));
            }
            BackendRequest::DelegateStaking(request) => {
                let delegation_id = request.delegation_id;
                let result = self.delegate_staking(request).await.map(|tx| (tx, delegation_id));
                Self::send_event(&self.event_tx, BackendEvent::DelegateStaking(result));
            }
            BackendRequest::SendDelegationToAddress(request) => {
                let result = self.send_delegation_to_address(request).await;
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::SendDelegationToAddress(result),
                );
            }
            BackendRequest::SubmitTx { wallet_id, tx } => {
                let result = self.submit_transaction(wallet_id, tx.take_tx()).await;
                Self::send_event(&self.event_tx, BackendEvent::Broadcast(result));
            }
            BackendRequest::TransactionList {
                wallet_id,
                account_id,
                skip,
            } => {
                let transaction_list_res =
                    self.load_transaction_list(wallet_id, account_id, skip).await;
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::TransactionList(wallet_id, account_id, transaction_list_res),
                );
            }
            BackendRequest::ConsoleCommand {
                wallet_id,
                account_id,
                command,
            } => {
                let res = self.handle_console_command(wallet_id, account_id, command).await;
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::ConsoleResponse(wallet_id, account_id, res),
                );
            }
            BackendRequest::Shutdown => unreachable!(),
        }
    }

    async fn handle_console_command(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
        command: String,
    ) -> Result<ConsoleCommand, BackendError> {
        let repl_command = get_repl_command(self.controller.is_cold(), false);
        let command = parse_input::<ColdWalletClient>(&command, &repl_command)
            .map_err(|e| BackendError::InvalidConsoleCommand(e.to_string()))?
            .ok_or(BackendError::EmptyConsoleCommand)?;

        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        match &mut wallet.controller {
            GuiHotColdController::Hot(_, c) => {
                select_acc_and_execute_cmd(c, account_id, command, &self.chain_config).await
            }
            GuiHotColdController::Cold(_, c) => {
                select_acc_and_execute_cmd(c, account_id, command, &self.chain_config).await
            }
        }
    }

    pub fn send_event(event_tx: &UnboundedSender<BackendEvent>, event: BackendEvent) {
        // The unbounded channel is used to avoid blocking the backend event loop.
        // Iced has a problem when it stops processing messages when the display is turned off.
        // It has been reproduced on Linux, and here is a bug reported on Windows: https://github.com/iced-rs/iced/issues/1870.
        // As a result, using the bounded channel can break staking, because once the channel is full, the backend event loop is paused.
        _ = event_tx.send(event);
    }

    async fn shutdown(self) {
        self.controller.shutdown();
        self.manager_join_handle.await.expect("Shutdown failed");
    }

    async fn update_wallets(&mut self) {
        for (wallet_id, wallet_data) in
            self.wallets.iter_mut().filter(|(_, wallet_data)| wallet_data.updated)
        {
            let controller = match &mut wallet_data.controller {
                GuiHotColdController::Cold(_, _) => continue,
                GuiHotColdController::Hot(w, _) => w,
            };

            wallet_data.updated = false;

            let best_block = controller.best_block().await.expect("shouldn't fail normally");
            let best_block = (best_block.id, best_block.height);

            if wallet_data.best_block != best_block {
                Self::send_event(
                    &self.low_priority_event_tx,
                    BackendEvent::WalletBestBlock(*wallet_id, best_block),
                );
                wallet_data.best_block = best_block;
            }

            for (account_id, account_data) in wallet_data.accounts.iter_mut() {
                // GuiWalletEvents will notify about wallet balance update
                // (when a wallet transaction is added/updated/removed)
                match get_account_balance(controller, account_id.account_index()).await {
                    Ok(balance) => Self::send_event(
                        &self.low_priority_event_tx,
                        BackendEvent::Balance(*wallet_id, *account_id, balance),
                    ),
                    Err(err) => {
                        log::error!("Address usage loading failed: {err}");
                    }
                };

                match controller.get_issued_addresses(account_id.account_index()).await {
                    Ok(addresses) => {
                        for info in addresses {
                            Self::send_event(
                                &self.low_priority_event_tx,
                                BackendEvent::NewAddress(AddressInfo::new(
                                    *wallet_id,
                                    *account_id,
                                    &info.index,
                                    info.address.into_string(),
                                )),
                            );
                        }
                    }
                    Err(err) => {
                        log::error!("Address usage loading failed: {err}");
                    }
                }

                // GuiWalletEvents will notify about stake pool balance update
                // (when a new wallet block is added/removed from the DB)
                account_data.update_pool_balance_and_delegations = true;

                // GuiWalletEvents will notify about transaction list
                // (when a wallet transaction is added/updated/removed)
                let transaction_list_res = controller
                    .get_transaction_list(
                        account_id.account_index(),
                        account_data.transaction_list_skip,
                        TRANSACTION_LIST_PAGE_COUNT,
                    )
                    .await;
                match transaction_list_res {
                    Ok(transaction_list) => {
                        Self::send_event(
                            &self.low_priority_event_tx,
                            BackendEvent::TransactionList(
                                *wallet_id,
                                *account_id,
                                Ok(transaction_list),
                            ),
                        );
                    }
                    Err(err) => {
                        log::error!("Transaction list loading failed: {err}");
                    }
                }
            }
        }

        // `get_stake_pool_balances` may fail if we ever start using remote RPC
        for (wallet_id, wallet_data) in self.wallets.iter_mut() {
            let controller = match &mut wallet_data.controller {
                GuiHotColdController::Hot(w, _) => w,
                GuiHotColdController::Cold(_, _) => continue,
            };
            for (account_id, account_data) in
                wallet_data.accounts.iter_mut().filter(|(_account_id, account_data)| {
                    account_data.update_pool_balance_and_delegations
                })
            {
                let pool_info_res = controller.list_staking_pools(account_id.account_index()).await;
                match pool_info_res {
                    Ok(staking_balance) => {
                        Self::send_event(
                            &self.low_priority_event_tx,
                            BackendEvent::StakingBalance(
                                *wallet_id,
                                *account_id,
                                BTreeMap::from_iter(staking_balance.into_iter().map(|info| {
                                    (
                                        info.pool_id
                                            .decode_object(&self.chain_config)
                                            .expect("valid addressable"),
                                        info,
                                    )
                                })),
                            ),
                        );
                        account_data.update_pool_balance_and_delegations = false;
                    }
                    Err(err) => {
                        log::error!("Staking balance loading failed: {err}");
                    }
                }

                let delegations_res =
                    controller.list_delegation_ids(account_id.account_index()).await;
                match delegations_res {
                    Ok(delegations_balance) => {
                        Self::send_event(
                            &self.low_priority_event_tx,
                            BackendEvent::DelegationsBalance(
                                *wallet_id,
                                *account_id,
                                BTreeMap::from_iter(delegations_balance.into_iter().map(|info| {
                                    (
                                        info.delegation_id
                                            .decode_object(&self.chain_config)
                                            .expect("valid addressable"),
                                        (
                                            info.pool_id
                                                .decode_object(&self.chain_config)
                                                .expect("valid addressable"),
                                            info.balance.amount(),
                                        ),
                                    )
                                })),
                            ),
                        );
                        account_data.update_pool_balance_and_delegations = false;
                    }
                    Err(err) => {
                        log::error!("Delegations loading failed: {err}");
                    }
                }
            }
        }
    }

    fn wallet_updated(&mut self, wallet_id: WalletId) {
        if let Some(wallet) = self.wallets.get_mut(&wallet_id) {
            wallet.updated = true;
        }
    }
}

async fn get_account_balance<N>(
    controller: &WalletRpc<N>,
    account_index: U31,
) -> Result<Balances, BackendError>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
{
    controller
        .get_balance(
            account_index,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        )
        .await
        .map_err(|e| BackendError::WalletError(e.to_string()))
}

async fn encrypt_action<T>(
    action: EncryptionAction,
    controller: &mut WalletRpc<T>,
    wallet_id: WalletId,
) -> Result<(WalletId, EncryptionState), BackendError>
where
    T: NodeInterface + Clone + Send + Sync + 'static,
{
    match action {
        EncryptionAction::SetPassword(password) => controller
            .encrypt_private_keys(password)
            .await
            .map(|()| (wallet_id, EncryptionState::EnabledUnlocked)),
        EncryptionAction::RemovePassword => controller
            .remove_private_key_encryption()
            .await
            .map(|()| (wallet_id, EncryptionState::Disabled)),
        EncryptionAction::Unlock(password) => controller
            .unlock_private_keys(password)
            .await
            .map(|()| (wallet_id, EncryptionState::EnabledUnlocked)),
        EncryptionAction::Lock => controller
            .lock_private_keys()
            .await
            .map(|()| (wallet_id, EncryptionState::EnabledLocked)),
    }
    .map_err(|err| BackendError::WalletError(err.to_string()))
}

async fn select_acc_and_execute_cmd<N>(
    c: &mut CommandHandler<WalletRpcHandlesClient<N>>,
    account_id: AccountId,
    command: ManageableWalletCommand,
    chain_config: &ChainConfig,
) -> Result<ConsoleCommand, BackendError>
where
    N: NodeInterface + Clone + Send + Sync + 'static + Debug,
{
    c.handle_manageable_wallet_command(
        chain_config,
        ManageableWalletCommand::WalletCommands(WalletCommand::SelectAccount {
            account_index: account_id.account_index(),
        }),
    )
    .await
    .map_err(|e| BackendError::WalletError(e.to_string()))?;
    c.handle_manageable_wallet_command(chain_config, command)
        .await
        .map_err(|e| BackendError::WalletError(e.to_string()))
}

pub async fn run(
    mut backend: Backend,
    mut request_rx: UnboundedReceiver<BackendRequest>,
    mut wallet_updated_rx: UnboundedReceiver<WalletId>,
    mut chainstate_event_handler: ChainstateEventHandler,
    mut p2p_event_handler: P2pEventHandler,
) {
    loop {
        tokio::select! {
            // Make event loop more efficient
            biased;

            request_opt = request_rx.recv() => {
                let request = request_opt.expect("UI channel closed unexpectedly");
                if matches!(request, BackendRequest::Shutdown) {
                    backend.shutdown().await;
                    return;
                } else {
                    backend.process_request(request).await;
                }
            }

            // Start this before starting the remaining background tasks
            // to reduce the chance of tasks being canceled (for efficiency)
            wallet_id = wallet_updated_rx.recv() => {
                let wallet_id = wallet_id.expect("wallet_updated_rx must be always open");
                backend.wallet_updated(wallet_id);
            }

            () = chainstate_event_handler.run() => {
                log::debug!("Chainstate channel closed, looks like the node has stopped");
                return
            }

            () = p2p_event_handler.run() => {
                log::debug!("P2P channel closed, looks like the node has stopped");
                return
            }
        }

        // Process all pending messages so that `update_wallets` is not needlessly called multiple times
        while let Ok(wallet_id) = wallet_updated_rx.try_recv() {
            backend.wallet_updated(wallet_id);
        }

        // Update UI on every loop iteration (can be after a UI request or after `wallet_notify` is triggered)
        backend.update_wallets().await;
    }
}

pub async fn run_cold(
    mut backend: Backend,
    mut request_rx: UnboundedReceiver<BackendRequest>,
    mut wallet_updated_rx: UnboundedReceiver<WalletId>,
) {
    loop {
        tokio::select! {
            // Make event loop more efficient
            biased;

            request_opt = request_rx.recv() => {
                let request = request_opt.expect("UI channel closed unexpectedly");
                if matches!(request, BackendRequest::Shutdown) {
                    backend.shutdown().await;
                    return;
                } else {
                    backend.process_request(request).await;
                }
            }

            // Start this before starting the remaining background tasks
            // to reduce the chance of tasks being canceled (for efficiency)
            wallet_id = wallet_updated_rx.recv() => {
                let wallet_id = wallet_id.expect("wallet_updated_rx must be always open");
                backend.wallet_updated(wallet_id);
            }
        }
    }
}

async fn forward_events(tx: GuiWalletEvents, mut rx: EventStream) {
    while rx.recv().await.is_some() {
        tx.notify()
    }
}
