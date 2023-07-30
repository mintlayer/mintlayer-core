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

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use common::{
    chain::{ChainConfig, GenBlock, SignedTransaction},
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id},
};
use crypto::key::hdkd::u31::U31;
use logging::log;
use node_lib::node_controller::NodeController;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use wallet::{
    account::{transaction_list::TransactionList, Currency},
    DefaultWallet,
};
use wallet_controller::{HandlesController, UtxoState, WalletHandlesClient};

use super::{
    chainstate_event_handler::ChainstateEventHandler,
    error::BackendError,
    messages::{
        AccountId, AccountInfo, AddressInfo, BackendEvent, BackendRequest, EncryptionAction,
        EncryptionState, SendRequest, StakeRequest, TransactionInfo, WalletId, WalletInfo,
    },
    p2p_event_handler::P2pEventHandler,
    parse_address, parse_coin_amount,
    wallet_events::GuiWalletEvents,
};

const TRANSACTION_LIST_PAGE_COUNT: usize = 10;

pub type GuiController = HandlesController<GuiWalletEvents>;

struct WalletData {
    controller: GuiController,
    best_block: (Id<GenBlock>, BlockHeight),
    accounts: BTreeMap<AccountId, AccountData>,
    updated: bool,
}

struct AccountData {
    /// How many transactions the user has seen and scrolled (can be 0, 10, 20, etc).
    /// The variable is stored here so that the backend can send transaction list updates automatically.
    transaction_list_skip: usize,

    /// If set, pool balances should be updated in the UI.
    /// The flag is necessary because the pool balances load requires RPC call and may fail.
    update_pool_balance: bool,
}

pub struct Backend {
    chain_config: Arc<ChainConfig>,

    /// The bounded sender is used so that the UI is not overloaded with messages.
    /// With an unbounded sender, high latency was experienced when wallet scan was enabled.
    event_tx: UnboundedSender<BackendEvent>,

    wallet_updated_tx: UnboundedSender<WalletId>,

    controller: NodeController,

    manager_join_handle: JoinHandle<()>,

    wallets: BTreeMap<WalletId, WalletData>,
}

impl Backend {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        event_tx: UnboundedSender<BackendEvent>,
        wallet_updated_tx: UnboundedSender<WalletId>,
        controller: NodeController,
        manager_join_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            chain_config,
            event_tx,
            wallet_updated_tx,
            controller,
            manager_join_handle,
            wallets: BTreeMap::new(),
        }
    }
    async fn open_wallet(&mut self, file_path: PathBuf) -> Result<WalletInfo, BackendError> {
        log::debug!("Try to open wallet file {file_path:?}...");

        let wallet = GuiController::open_wallet(Arc::clone(&self.chain_config), file_path.clone())
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

        let wallet = GuiController::create_wallet(
            Arc::clone(&self.chain_config),
            file_path.clone(),
            mnemonic,
            None,
        )
        .map_err(|e| BackendError::WalletError(e.to_string()))?;

        self.add_wallet(file_path, wallet).await
    }

    fn get_account_data(_controller: &GuiController, _account_index: U31) -> AccountData {
        AccountData {
            transaction_list_skip: 0,
            update_pool_balance: true,
        }
    }

    fn get_account_info(controller: &GuiController, account_index: U31) -> AccountInfo {
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

        let wallet_events = GuiWalletEvents::new(wallet_id, self.wallet_updated_tx.clone());

        let controller = HandlesController::new(
            Arc::clone(&self.chain_config),
            handles_client,
            wallet,
            wallet_events,
        );
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

        let wallet_data = WalletData {
            controller,
            accounts: accounts_data,
            best_block,
            updated: false,
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
        name: String,
    ) -> Result<(WalletId, AccountId, AccountInfo), BackendError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?;

        let name = name.trim().to_owned();
        let name = (!name.is_empty()).then_some(name);

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

        let transaction_status = wallet
            .controller
            .send_to_address(account_id.account_index(), address, amount)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { transaction_status })
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

        let transaction_status = wallet
            .controller
            .create_stake_pool_tx(
                account_id.account_index(),
                amount,
                None,
                // TODO: get value from gui
                PerThousand::new(1000).expect("Must not fail"),
                Amount::ZERO,
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { transaction_status })
    }

    async fn broadcast(&mut self, transaction: SignedTransaction) -> Result<(), BackendError> {
        let tx_status = self
            .controller
            .p2p
            .call_async_mut(|p2p| p2p.submit_transaction(transaction))
            .await
            .map_err(|e| BackendError::RpcError(e.to_string()))?
            .map_err(|e| BackendError::RpcError(e.to_string()))?;
        match tx_status {
            mempool::TxStatus::InMempool => Ok(()),
            mempool::TxStatus::InOrphanPool => {
                // Mempool should reject the transaction and not return `InOrphanPool`
                log::warn!("The transaction has been added to the orphan pool.");
                Ok(())
            }
        }
    }

    fn get_account_balance(
        controller: &GuiController,
        account_index: U31,
    ) -> BTreeMap<Currency, Amount> {
        controller
            .get_balance(account_index, UtxoState::Confirmed.into())
            .expect("get_balance should not fail normally")
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
                Self::send_event(&self.event_tx, BackendEvent::OpenWallet(open_res));
            }
            BackendRequest::CreateWallet {
                mnemonic,
                file_path,
            } => {
                let import_res = self.create_wallet(mnemonic, file_path).await;
                Self::send_event(&self.event_tx, BackendEvent::ImportWallet(import_res));
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
                let transaction_list_res = self.load_transaction_list(wallet_id, account_id, skip);
                Self::send_event(
                    &self.event_tx,
                    BackendEvent::TransactionList(wallet_id, account_id, transaction_list_res),
                );
            }
            BackendRequest::Shutdown => unreachable!(),
        }
    }

    pub fn send_event(event_tx: &UnboundedSender<BackendEvent>, event: BackendEvent) {
        // The unbounded channel is used to avoid blocking the backend event loop.
        // Iced has a problem when it stops processing messages when the display is turned off.
        // It has been reproduced on Lunux, and here is a bug reported on Windows: https://github.com/iced-rs/iced/issues/1870.
        // As a result, using the bounded channel can break staking, because once the channel is full, the backend event loop is paused.
        _ = event_tx.send(event);
    }

    async fn shutdown(self) {
        self.controller.shutdown_trigger.initiate();
        self.manager_join_handle.await.expect("Shutdown failed");
    }

    async fn update_wallets(&mut self) {
        for (wallet_id, wallet_data) in
            self.wallets.iter_mut().filter(|(_, wallet_data)| wallet_data.updated)
        {
            wallet_data.updated = false;

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
                let transaction_list_res = wallet_data.controller.get_transaction_list(
                    account_id.account_index(),
                    account_data.transaction_list_skip,
                    TRANSACTION_LIST_PAGE_COUNT,
                );
                match transaction_list_res {
                    Ok(transaction_list) => {
                        Self::send_event(
                            &self.event_tx,
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
            for (account_id, account_data) in wallet_data
                .accounts
                .iter_mut()
                .filter(|(_account_id, account_data)| account_data.update_pool_balance)
            {
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

    async fn wallet_sync(&mut self) {
        if self.wallets.is_empty() {
            std::future::pending::<()>().await;
        }

        let wallet_tasks = self.wallets.values_mut().map(|wallet| wallet.controller.run());
        futures::future::join_all(wallet_tasks).await;
    }

    fn wallet_updated(&mut self, wallet_id: WalletId) {
        if let Some(wallet) = self.wallets.get_mut(&wallet_id) {
            wallet.updated = true;
        }
    }
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

            // Start wallet sync as last
            _ = backend.wallet_sync() => {},
        }

        // Process all pending messages so that `update_wallets` is not needlessly called multiple times
        while let Ok(wallet_id) = wallet_updated_rx.try_recv() {
            backend.wallet_updated(wallet_id);
        }

        // Update UI on every loop iteration (can be after a UI request or after `wallet_notify` is triggered)
        backend.update_wallets().await;
    }
}
