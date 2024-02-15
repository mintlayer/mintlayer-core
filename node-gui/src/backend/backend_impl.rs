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
    address::Address,
    chain::{ChainConfig, GenBlock},
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
    account::{currency_grouper::Currency, transaction_list::TransactionList},
    DefaultWallet,
};
use wallet_controller::{
    read::ReadOnlyController, synced_controller::SyncedController, ControllerConfig,
    HandlesController, UtxoState, WalletHandlesClient,
};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

use super::{
    chainstate_event_handler::ChainstateEventHandler,
    error::BackendError,
    messages::{
        AccountId, AccountInfo, AddressInfo, BackendEvent, BackendRequest, CreateDelegationRequest,
        DelegateStakingRequest, EncryptionAction, EncryptionState, SendDelegateToAddressRequest,
        SendRequest, StakeRequest, TransactionInfo, WalletId, WalletInfo,
    },
    p2p_event_handler::P2pEventHandler,
    parse_address, parse_coin_amount,
    wallet_events::GuiWalletEvents,
};

const TRANSACTION_LIST_PAGE_COUNT: usize = 10;
/// In which top N MB should we aim for our transactions to be in the mempool
/// e.g. for 5, we aim to be in the top 5 MB of transactions based on paid fees
/// This is to avoid getting trimmed off the lower end if the mempool runs out of memory
const IN_TOP_X_MB: usize = 5;

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

    controller: NodeController,

    manager_join_handle: JoinHandle<()>,

    wallets: BTreeMap<WalletId, WalletData>,
}

impl Backend {
    pub fn new(
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
            controller,
            manager_join_handle,
            wallets: BTreeMap::new(),
        }
    }
    async fn open_wallet(&mut self, file_path: PathBuf) -> Result<WalletInfo, BackendError> {
        log::debug!("Try to open wallet file {file_path:?}...");

        let wallet =
            GuiController::open_wallet(Arc::clone(&self.chain_config), file_path.clone(), None)
                .map_err(|e| BackendError::WalletError(e.to_string()))?;

        self.add_wallet(file_path, wallet).await
    }

    async fn recover_wallet(
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

        let wallet = GuiController::recover_wallet(
            Arc::clone(&self.chain_config),
            file_path.clone(),
            mnemonic,
            None,
            StoreSeedPhrase::Store,
        )
        .map_err(|e| BackendError::WalletError(e.to_string()))?;

        self.add_wallet(file_path, wallet).await
    }

    fn get_account_data(_controller: &GuiController, _account_index: U31) -> AccountData {
        AccountData {
            transaction_list_skip: 0,
            update_pool_balance_and_delegations: true,
        }
    }

    fn get_account_info(controller: &GuiController, account_index: U31) -> AccountInfo {
        let name = controller
            .wallet_info()
            .account_names
            .into_iter()
            .nth(account_index.into_u32() as usize)
            .flatten();
        let controller = controller.readonly_controller(account_index);
        let transaction_list = controller
            .get_transaction_list(0, TRANSACTION_LIST_PAGE_COUNT)
            .expect("load_transaction_list failed");
        AccountInfo {
            name,
            addresses: controller
                .get_all_issued_addresses()
                .expect("get_all_issued_addresses should not fail normally"),
            staking_enabled: false,
            balance: Self::get_account_balance(&controller),
            staking_balance: Default::default(),
            delegations_balance: Default::default(),
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

        let controller = HandlesController::new_unsynced(
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

    async fn new_address(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
    ) -> Result<AddressInfo, BackendError> {
        let (index, address) = self
            .synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .new_address()
            .map_err(|e| BackendError::WalletError(e.to_string()))?;
        Ok(AddressInfo {
            wallet_id,
            account_id,
            index,
            address,
        })
    }

    async fn toggle_staking(
        &mut self,
        wallet_id: WalletId,
        account_id: AccountId,
        enabled: bool,
    ) -> Result<(WalletId, AccountId, bool), BackendError> {
        if enabled {
            self.synced_wallet_controller(wallet_id, account_id.account_index())
                .await?
                .start_staking()
                .map_err(|e| BackendError::WalletError(e.to_string()))?;
        } else {
            self.wallets
                .get_mut(&wallet_id)
                .ok_or(BackendError::UnknownWalletIndex(wallet_id))?
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

        let address = parse_address(&self.chain_config, &address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?;
        let amount = parse_coin_amount(&self.chain_config, &amount)
            .ok_or(BackendError::InvalidAmount(amount))?;

        // TODO: add support for utxo selection in the GUI
        self.synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .send_to_address(address, amount, vec![])
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { wallet_id })
    }

    async fn synced_wallet_controller(
        &mut self,
        wallet_id: WalletId,
        account_index: U31,
    ) -> Result<SyncedController<'_, WalletHandlesClient, GuiWalletEvents>, BackendError> {
        self.wallets
            .get_mut(&wallet_id)
            .ok_or(BackendError::UnknownWalletIndex(wallet_id))?
            .controller
            // TODO: add option to select from GUI
            .synced_controller(
                account_index,
                ControllerConfig {
                    in_top_x_mb: IN_TOP_X_MB,
                },
            )
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))
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
            .decode_object(&self.chain_config)
            .map_err(|e| BackendError::AddressError(e.to_string()))?;

        self.synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .create_stake_pool_tx(amount, decommission_key, mpt, cost_per_block)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { wallet_id })
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

        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|e| BackendError::AddressError(e.to_string()))?;

        let delegation_key = parse_address(&self.chain_config, &delegation_address)
            .map_err(|err| BackendError::AddressError(err.to_string()))?;

        self.synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .create_delegation(delegation_key, pool_id)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { wallet_id })
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

        self.synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .delegate_staking(delegation_amount, delegation_id)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { wallet_id })
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

        let delegation_id = Address::from_str(&self.chain_config, &delegation_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|e| BackendError::AddressError(e.to_string()))?;

        self.synced_wallet_controller(wallet_id, account_id.account_index())
            .await?
            .send_to_address_from_delegation(address, amount, delegation_id)
            .await
            .map_err(|e| BackendError::WalletError(e.to_string()))?;

        Ok(TransactionInfo { wallet_id })
    }

    fn get_account_balance(
        controller: &ReadOnlyController<WalletHandlesClient>,
    ) -> BTreeMap<Currency, Amount> {
        controller
            .get_balance(UtxoState::Confirmed.into(), WithLocked::Unlocked)
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
            .readonly_controller(account_id.account_index())
            .get_transaction_list(account.transaction_list_skip, TRANSACTION_LIST_PAGE_COUNT)
            .map_err(|e| BackendError::WalletError(e.to_string()))
    }

    async fn process_request(&mut self, request: BackendRequest) {
        match request {
            BackendRequest::OpenWallet { file_path } => {
                let open_res = self.open_wallet(file_path).await;
                Self::send_event(&self.event_tx, BackendEvent::OpenWallet(open_res));
            }
            BackendRequest::RecoverWallet {
                mnemonic,
                file_path,
            } => {
                let import_res = self.recover_wallet(mnemonic, file_path).await;
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
        // It has been reproduced on Linux, and here is a bug reported on Windows: https://github.com/iced-rs/iced/issues/1870.
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
                    &self.low_priority_event_tx,
                    BackendEvent::WalletBestBlock(*wallet_id, best_block),
                );
                wallet_data.best_block = best_block;
            }

            for (account_id, account_data) in wallet_data.accounts.iter_mut() {
                let controller =
                    wallet_data.controller.readonly_controller(account_id.account_index());
                // GuiWalletEvents will notify about wallet balance update
                // (when a wallet transaction is added/updated/removed)
                let balance = Self::get_account_balance(&controller);
                Self::send_event(
                    &self.low_priority_event_tx,
                    BackendEvent::Balance(*wallet_id, *account_id, balance),
                );

                // GuiWalletEvents will notify about stake pool balance update
                // (when a new wallet block is added/removed from the DB)
                account_data.update_pool_balance_and_delegations = true;

                // GuiWalletEvents will notify about transaction list
                // (when a wallet transaction is added/updated/removed)
                let transaction_list_res = controller.get_transaction_list(
                    account_data.transaction_list_skip,
                    TRANSACTION_LIST_PAGE_COUNT,
                );
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
            for (account_id, account_data) in
                wallet_data.accounts.iter_mut().filter(|(_account_id, account_data)| {
                    account_data.update_pool_balance_and_delegations
                })
            {
                let pool_info_res = wallet_data
                    .controller
                    .readonly_controller(account_id.account_index())
                    .get_pool_ids()
                    .await;
                match pool_info_res {
                    Ok(staking_balance) => {
                        Self::send_event(
                            &self.low_priority_event_tx,
                            BackendEvent::StakingBalance(
                                *wallet_id,
                                *account_id,
                                BTreeMap::from_iter(
                                    staking_balance
                                        .into_iter()
                                        .map(|(id, data, balance)| (id, (data, balance))),
                                ),
                            ),
                        );
                        account_data.update_pool_balance_and_delegations = false;
                    }
                    Err(err) => {
                        log::error!("Staking balance loading failed: {err}");
                    }
                }

                let delegations_res = wallet_data
                    .controller
                    .readonly_controller(account_id.account_index())
                    .get_delegations()
                    .await;
                match delegations_res {
                    Ok(delegations_balance) => {
                        Self::send_event(
                            &self.low_priority_event_tx,
                            BackendEvent::DelegationsBalance(
                                *wallet_id,
                                *account_id,
                                BTreeMap::from_iter(
                                    delegations_balance
                                        .into_iter()
                                        .map(|(del, pool, balance)| (del, (pool, balance))),
                                ),
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
