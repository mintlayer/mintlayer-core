// Copyright (c) 2021-2023 RBB S.r.l
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

pub mod messages;
pub mod wallet_events;

use chainstate::ChainstateEvent;
use common::address::{Address, AddressError};
use common::chain::{ChainConfig, GenBlock, SignedTransaction};
use common::primitives::{Amount, BlockHeight, Id};
use common::time_getter::TimeGetter;
use crypto::key::hdkd::u31::U31;
use logging::log;
use node_lib::node_controller::NodeController;
use p2p::P2pEvent;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::BTreeMap, fmt::Debug};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use utils::tap_error_log::LogError;
use wallet::account::transaction_list::TransactionList;
use wallet::account::Currency;
use wallet::DefaultWallet;
use wallet_controller::{HandlesController, UtxoState, WalletHandlesClient};

use self::messages::{
    AccountId, AccountInfo, AddressInfo, BackendEvent, BackendRequest, EncryptionAction,
    EncryptionState, SendRequest, StakeRequest, TransactionInfo, WalletId, WalletInfo,
};
use self::wallet_events::GuiWalletEvents;

const TRANSACTION_LIST_PAGE_COUNT: usize = 10;

#[derive(Debug)]
pub struct BackendControls {
    pub initialized_node: InitializedNode,
    pub backend_sender: BackendSender,
    pub backend_receiver: UnboundedReceiver<BackendEvent>,
}

// Wrap `UnboundedSender` without Clone
#[derive(Debug)]
pub struct BackendSender {
    request_tx: UnboundedSender<BackendRequest>,
}

impl BackendSender {
    fn new(request_tx: UnboundedSender<BackendRequest>) -> Self {
        Self { request_tx }
    }

    pub fn send(&self, msg: BackendRequest) {
        let _ = self.request_tx.send(msg);
    }
}

struct WalletData {
    controller: HandlesController,
    wallet_events: GuiWalletEvents,
    best_block: (Id<GenBlock>, BlockHeight),
    accounts: BTreeMap<AccountId, AccountData>,
}

struct AccountData {
    transaction_list_skip: usize,

    /// If set, pool balances should be updated in the UI.
    /// This is necessary because the pool balances load requres RPC call and may fail.
    update_pool_balance: bool,
}

struct Backend {
    chain_config: Arc<ChainConfig>,
    event_tx: UnboundedSender<BackendEvent>,
    controller: NodeController,
    manager_join_handle: JoinHandle<()>,
    wallets: BTreeMap<WalletId, WalletData>,
    wallet_notify: Arc<Notify>,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum BackendError {
    #[error("Wallet error: {0}")]
    WalletError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Unknown wallet index: {0:?}")]
    UnknownWalletIndex(WalletId),
    #[error("Unknown account index: {0:?}/{0:?}")]
    UnknownAccountIndex(WalletId, AccountId),
    #[error("Invalid address: {0}")]
    AddressError(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
}

fn parse_coin_amount(chain_config: &ChainConfig, value: &str) -> Option<Amount> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
}

fn parse_address(chain_config: &ChainConfig, address: &str) -> Result<Address, AddressError> {
    Address::from_str(chain_config, address)
}

impl Backend {
    async fn open_wallet(&mut self, file_path: PathBuf) -> Result<WalletInfo, BackendError> {
        log::debug!("Try to open wallet file {file_path:?}...");

        let wallet =
            HandlesController::open_wallet(Arc::clone(&self.chain_config), file_path.clone())
                .map_err(|e| BackendError::WalletError(e.to_string()))?;

        self.add_wallet(file_path, wallet).await
    }

    async fn create_wallet(
        &mut self,
        mnemonic: wallet_controller::mnemonic::Mnemonic,
        file_path: PathBuf,
    ) -> Result<WalletInfo, BackendError> {
        log::debug!("Try to create wallet file {file_path:?}...");

        // The UI frontend must have already warned the user that the file will be overwritten
        if file_path.exists() {
            std::fs::remove_file(&file_path)
                .map_err(|err| BackendError::WalletError(err.to_string()))?;
        }

        let wallet = HandlesController::create_wallet(
            Arc::clone(&self.chain_config),
            file_path.clone(),
            mnemonic,
            None,
        )
        .map_err(|e| BackendError::WalletError(e.to_string()))?;

        self.add_wallet(file_path, wallet).await
    }

    fn get_account_data(_controller: &HandlesController, _account_index: U31) -> AccountData {
        AccountData {
            transaction_list_skip: 0,
            update_pool_balance: true,
        }
    }

    fn get_account_balance(
        controller: &HandlesController,
        account_index: U31,
    ) -> BTreeMap<Currency, Amount> {
        controller
            .get_balance(account_index, UtxoState::Confirmed.into())
            .expect("get_balance should not fail normally")
    }

    fn get_account_info(controller: &HandlesController, account_index: U31) -> AccountInfo {
        let name = controller
            .account_names()
            .nth(account_index.into_u32() as usize)
            .cloned()
            .flatten();
        let transaction_list = controller
            .get_transaction_list(account_index, 0, TRANSACTION_LIST_PAGE_COUNT)
            .expect("load_transaction_list failed");
        AccountInfo {
            name,
            addresses: controller
                .get_all_issued_addresses(account_index)
                .expect("get_all_issued_addresses should not fail normally"),
            staking_enabled: false,
            balance: Self::get_account_balance(controller, account_index),
            staking_balance: BTreeMap::new(),
            transaction_list,
        }
    }

    async fn add_wallet(
        &mut self,
        file_path: PathBuf,
        wallet: DefaultWallet,
    ) -> Result<WalletInfo, BackendError> {
        let handles_client = WalletHandlesClient::new(
            self.controller.chainstate.clone(),
            self.controller.mempool.clone(),
            self.controller.block_prod.clone(),
            self.controller.p2p.clone(),
        )
        .await
        .map_err(|e| BackendError::WalletError(e.to_string()))?;

        let wallet_id = WalletId::new();
        let encryption = if wallet.is_encrypted() {
            EncryptionState::EnabledLocked
        } else {
            EncryptionState::Disabled
        };

        let account_indexes = wallet.account_indexes().cloned().collect::<Vec<_>>();

        let controller =
            HandlesController::new(Arc::clone(&self.chain_config), handles_client, wallet);
        let best_block = controller.best_block();

        let accounts_info = account_indexes
            .iter()
            .map(|account_index| {
                (
                    AccountId::new(*account_index),
                    Self::get_account_info(&controller, *account_index),
                )
            })
            .collect();

        let accounts_data = account_indexes
            .iter()
            .map(|account_index| {
                (
                    AccountId::new(*account_index),
                    Self::get_account_data(&controller, *account_index),
                )
            })
            .collect();

        let wallet_events = GuiWalletEvents::new(Arc::clone(&self.wallet_notify));

        let wallet_data = WalletData {
            controller,
            wallet_events,
            accounts: accounts_data,
            best_block,
        };

        let wallet_info = WalletInfo {
            wallet_id,
            path: file_path,
            encryption,
            accounts: accounts_info,
            best_block,
        };

        self.wallets.insert(wallet_id, wallet_data);

        Ok(wallet_info)
    }

    fn update_encryption(
        &mut self,
        wallet_id: WalletId,
        action: EncryptionAction,
    ) -> Result<(WalletId, EncryptionState), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let res = match action {
            EncryptionAction::SetPassword(password) => wallet
                .controller
                .encrypt_wallet(&Some(password))
                .map(|()| (wallet_id, EncryptionState::EnabledUnlocked)),
            EncryptionAction::RemovePassword => wallet
                .controller
                .encrypt_wallet(&None)
                .map(|()| (wallet_id, EncryptionState::Disabled)),
            EncryptionAction::Unlock(password) => wallet
                .controller
                .unlock_wallet(&password)
                .map(|()| (wallet_id, EncryptionState::EnabledUnlocked)),
            EncryptionAction::Lock => wallet
                .controller
                .lock_wallet()
                .map(|()| (wallet_id, EncryptionState::EnabledLocked)),
        };

        res.map_err(|err| BackendError::WalletError(err.to_string()))
    }

    fn new_account(
        &mut self,
        wallet_id: WalletId,
        name: Option<String>,
    ) -> Result<(WalletId, AccountId, AccountInfo), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let (account_index, _name) = wallet
            .controller
            .create_account(name)
            .map_err(|err| BackendError::WalletError(err.to_string()))?;

        let account_id = AccountId::new(account_index);
        let account_info = Self::get_account_info(&wallet.controller, account_index);
        let account_data = Self::get_account_data(&wallet.controller, account_index);

        wallet.accounts.insert(account_id, account_data);

        Ok((wallet_id, account_id, account_info))
    }

    fn new_address(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
    ) -> Result<AddressInfo, BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;
        let (index, address) = wallet
            .controller
            .new_address(account_id.account_index())
            .map_err(|e| BackendError::WalletError(e.to_string()))?;
        Ok(AddressInfo {
            wallet_id,
            account_id,
            index,
            address,
        })
    }

    fn toggle_staking(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
        enabled: bool,
    ) -> Result<(WalletId, AccountId, bool), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;
        if enabled {
            wallet
                .controller
                .start_staking(account_id.account_index())
                .map_err(|e| BackendError::WalletError(e.to_string()))?;
        } else {
            wallet
                .controller
                .stop_staking(account_id.account_index())
                .map_err(|e| BackendError::WalletError(e.to_string()))?;
        }
        Ok((wallet_id, account_id, enabled))
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

        let wallet = self
            .wallets
            .get_mut(&send_request.wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let address = parse_address(&self.chain_config, &address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?;
        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidAmount(amount))?;

        let transaction = wallet
            .controller
            .send_to_address(
                account_id.account_index(),
                address,
                amount,
                &mut wallet.wallet_events,
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { transaction })
    }

    async fn stake_amount(
        &mut self,
        stake_request: StakeRequest,
    ) -> Result<TransactionInfo, BackendError> {
        let StakeRequest {
            wallet_id,
            account_id,
            amount,
        } = stake_request;

        let wallet = self
            .wallets
            .get_mut(&stake_request.wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidAmount(amount))?;

        let transaction = wallet
            .controller
            .create_stake_pool_tx(
                account_id.account_index(),
                amount,
                None,
                &mut wallet.wallet_events,
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { transaction })
    }

    async fn broadcast(&mut self, transaction: SignedTransaction) -> Result<(), BackendError> {
        let _tx_status = self
            .controller
            .p2p
            .call_async_mut(|p2p| p2p.submit_transaction(transaction))
            .await
            .map_err(|e| BackendError::RpcError(e.to_string()))?
            .map_err(|e| BackendError::RpcError(e.to_string()));
        Ok(())
    }

    fn load_transaction_list(
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
            .controller
            .get_transaction_list(
                account_id.account_index(),
                account.transaction_list_skip,
                TRANSACTION_LIST_PAGE_COUNT,
            )
            .map_err(|e| BackendError::WalletError(e.to_string()))
    }

    async fn process_request(&mut self, request: BackendRequest) {
        match request {
            BackendRequest::OpenWallet { file_path } => {
                let open_res = self.open_wallet(file_path).await;
                Self::send_event(&self.event_tx, BackendEvent::OpenWallet(open_res))
            }
            BackendRequest::CreateWallet {
                mnemonic,
                file_path,
            } => {
                let import_res = self.create_wallet(mnemonic, file_path).await;
                Self::send_event(&self.event_tx, BackendEvent::ImportWallet(import_res))
            }
            BackendRequest::CloseWallet(wallet_id) => {
                if let Some(wallet) = self.wallets.remove(&wallet_id) {
                    drop(wallet);
                    Self::send_event(&self.event_tx, BackendEvent::CloseWallet(wallet_id));
                }
            }

            BackendRequest::UpdateEncryption { wallet_id, action } => {
                let res = self.update_encryption(wallet_id, action);
                Self::send_event(&self.event_tx, BackendEvent::UpdateEncryption(res));
            }

            BackendRequest::NewAccount { wallet_id, name } => {
                let res = self.new_account(wallet_id, name);
                Self::send_event(&self.event_tx, BackendEvent::NewAccount(res));
            }

            BackendRequest::NewAddress(wallet_id, account_id) => {
                let address_res = self.new_address(wallet_id, account_id);
                Self::send_event(&self.event_tx, BackendEvent::NewAddress(address_res));
            }
            BackendRequest::ToggleStaking(wallet_id, account_id, enabled) => {
                let toggle_res = self.toggle_staking(wallet_id, account_id, enabled);
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
            BackendRequest::Broadcast(transaction) => {
                let broadcast_res = self.broadcast(transaction).await;
                Self::send_event(&self.event_tx, BackendEvent::Broadcast(broadcast_res));
            }
            BackendRequest::TransactionList {
                wallet_id,
                account_id,
                skip,
            } => {
                let transaction_list = self
                    .load_transaction_list(wallet_id, account_id, skip)
                    .expect("load_transaction_list failed");
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::TransactionList(wallet_id, account_id, transaction_list),
                );
            }
            BackendRequest::Shutdown => unreachable!(),
        }
    }

    fn send_event(event_tx: &UnboundedSender<BackendEvent>, event: BackendEvent) {
        _ = event_tx.send(event);
    }

    async fn shutdown(self) {
        self.controller.shutdown_trigger.initiate();
        self.manager_join_handle.await.expect("Shutdown failed");
    }

    async fn update_wallets(&mut self) {
        for (wallet_id, wallet_data) in self
            .wallets
            .iter_mut()
            .filter(|(_, wallet_data)| wallet_data.wallet_events.is_set())
        {
            wallet_data.wallet_events.reset();

            let best_block = wallet_data.controller.best_block();
            if wallet_data.best_block != best_block {
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::WalletBestBlock(*wallet_id, best_block),
                );
                wallet_data.best_block = best_block;
            }

            for (account_id, account_data) in wallet_data.accounts.iter_mut() {
                // GuiWalletEvents will notify about wallet balance update
                // (when a wallet transaction is added/updated/removed)
                let balance =
                    Self::get_account_balance(&wallet_data.controller, account_id.account_index());
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::Balance(*wallet_id, *account_id, balance),
                );

                // GuiWalletEvents will notify about stake pool balance update
                // (when a new wallet block is added/removed from the DB)
                account_data.update_pool_balance = true;

                // GuiWalletEvents will notify about transaction list
                // (when a wallet transaction is added/updated/removed)
                let transaction_list = wallet_data
                    .controller
                    .get_transaction_list(
                        account_id.account_index(),
                        account_data.transaction_list_skip,
                        TRANSACTION_LIST_PAGE_COUNT,
                    )
                    .expect("load_transaction_list failed");
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::TransactionList(*wallet_id, *account_id, transaction_list),
                );
            }
        }

        for (wallet_id, wallet_data) in self.wallets.iter_mut() {
            for (account_id, account_data) in wallet_data.accounts.iter_mut() {
                if account_data.update_pool_balance {
                    let staking_balance_res = wallet_data
                        .controller
                        .get_stake_pool_balances(account_id.account_index())
                        .await;
                    match staking_balance_res {
                        Ok(staking_balance) => {
                            Self::send_event(
                                &self.event_tx,
                                BackendEvent::StakingBalance(
                                    *wallet_id,
                                    *account_id,
                                    staking_balance.clone(),
                                ),
                            );
                            account_data.update_pool_balance = false;
                        }
                        Err(err) => {
                            log::error!("Staking balance loading failed: {err}");
                        }
                    }
                }
            }
        }
    }

    async fn run(&mut self) {
        if self.wallets.is_empty() {
            std::future::pending::<()>().await;
        }

        let wallet_tasks = self
            .wallets
            .values_mut()
            .map(|wallet| wallet.controller.run(&mut wallet.wallet_events));
        futures::future::join_all(wallet_tasks).await;
    }
}

#[derive(Debug)]
pub struct InitializedNode {
    pub chain_config: Arc<ChainConfig>,
    pub best_block_id: Id<GenBlock>,
    pub best_block_height: BlockHeight,
}

pub async fn node_initialize(_time_getter: TimeGetter) -> anyhow::Result<BackendControls> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let opts = node_lib::Options::from_args(std::env::args_os());
    logging::init_logging::<&std::path::Path>(None);
    logging::log::info!("Command line options: {opts:?}");

    let node = node_lib::setup(opts).await?;

    let controller = node.controller().clone();

    let manager_join_handle = tokio::spawn(async move { node.main().await });

    // Subscribe to chainstate before getting the current best_block!
    let (chainstate_event_tx, mut chainstate_event_rx) = unbounded_channel();
    controller
        .chainstate
        .call_mut(|this| {
            this.subscribe_to_events(Arc::new(move |chainstate_event: ChainstateEvent| {
                _ = chainstate_event_tx
                    .send(chainstate_event)
                    .log_err_pfx("Chainstate subscriber failed to send new tip");
            }));
        })
        .await
        .expect("Failed to subscribe to chainstate");

    // TODO: Fix race in p2p events subscribe (if some peers are connected before the subscription is complete)
    let (p2p_event_tx, mut p2p_event_rx) = unbounded_channel();
    controller
        .p2p
        .call_mut(|this| {
            this.subscribe_to_events(Arc::new(move |p2p_event: P2pEvent| {
                _ = p2p_event_tx
                    .send(p2p_event)
                    .log_err_pfx("P2P subscriber failed to send new event");
            }))
        })
        .await
        .expect("Failed to subscribe to P2P event")
        .expect("Failed to subscribe to P2P event");

    let chain_config =
        controller.chainstate.call(|this| Arc::clone(this.get_chain_config())).await?;
    let best_block = controller.chainstate.call(|this| this.get_best_block_index()).await??;

    let (request_tx, mut request_rx) = unbounded_channel();
    let (event_tx, event_rx) = unbounded_channel();

    let initialized_node = InitializedNode {
        chain_config: Arc::clone(&chain_config),
        best_block_id: best_block.block_id(),
        best_block_height: best_block.block_height(),
    };

    let backend_controls = BackendControls {
        initialized_node,
        backend_sender: BackendSender::new(request_tx),
        backend_receiver: event_rx,
    };

    tokio::spawn(async move {
        let wallet_notify = Arc::new(Notify::new());

        let mut backend = Backend {
            chain_config,
            event_tx,
            controller,
            manager_join_handle,
            wallets: BTreeMap::new(),
            wallet_notify: Arc::clone(&wallet_notify),
        };

        loop {
            tokio::select! {
                chainstate_event_opt = chainstate_event_rx.recv() => {
                    match chainstate_event_opt {
                        Some(event) => {
                            Backend::send_event(&backend.event_tx, BackendEvent::Chainstate(event));
                        },
                        None => {
                            // Node is stopped
                            log::debug!("Chainstate channel closed");
                            return
                        },
                    }
                }

                p2p_event_opt = p2p_event_rx.recv() => {
                    match p2p_event_opt {
                        Some(event) => {
                            Backend::send_event(&backend.event_tx, BackendEvent::P2p(event));
                        },
                        None => {
                            // Node is stopped
                            log::debug!("P2P channel closed");
                            return
                        },
                    }
                }

                request_opt = request_rx.recv() => {
                    let request = request_opt.expect("UI channel closed unexpectedly");
                    if matches!(request, BackendRequest::Shutdown) {
                        backend.shutdown().await;
                        return;
                    } else {
                        backend.process_request(request).await;
                    }
                }

                _ = wallet_notify.notified() => {}

                // Wallet sync can be inefficient because it is interrupted as soon as another branch is ready
                _ = backend.run() => {},
            }

            backend.update_wallets().await;
        }
    });

    Ok(backend_controls)
}
