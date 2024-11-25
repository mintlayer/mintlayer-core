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

mod backend_impl;
mod chainstate_event_handler;
mod error;
pub mod messages;
mod p2p_event_handler;
mod wallet_events;

use self::error::BackendError;
use self::messages::BackendEvent;
use crate::chainstate_event_handler::ChainstateEventHandler;
use crate::p2p_event_handler::P2pEventHandler;
use anyhow::{Error, Result};
use backend_impl::{Backend, ImportOrCreate};
use chainstate::ChainInfo;
use common::address::{Address, AddressError};
use common::chain::SignedTransaction;
use common::chain::{ChainConfig, DelegationId, Destination};
use common::primitives::{Amount, BlockHeight};
use crypto::key::hdkd::u31::U31;
use messages::{
    AccountId, AccountInfo, AddressInfo, CreateDelegationRequest, DecommissionPoolRequest,
    DelegateStakingRequest, EncryptionAction, EncryptionState, SendDelegateToAddressRequest,
    SendRequest, StakeRequest, TransactionInfo, WalletId, WalletInfo,
};
use node_lib::{Command, RunOptions};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::async_runtime::RwLock;
use tauri::AppHandle;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use wallet_cli_commands::ConsoleCommand;
use wallet_types::wallet_type::WalletType;
struct AppState {
    initialized_node: RwLock<Option<InitializedNode>>,
    backend: RwLock<Option<Arc<Backend>>>,
}

static GLOBAL_APP_HANDLE: OnceCell<AppHandle> = OnceCell::new();

pub struct BackendControls {
    pub initialized_node: InitializedNode,
    pub low_priority_backend_receiver: UnboundedReceiver<BackendEvent>,
    pub backend: Arc<Backend>,
}

/// `UnboundedSender` wrapper, used to make sure there is only one instance and it doesn't get cloned
///
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum InitNetwork {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WalletMode {
    Cold,
    Hot,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenCreateWalletRequest {
    mnemonic: String,
    file_path: String,
    import: bool,
    wallet_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenWalletRequest {
    file_path: String,
    wallet_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendAmountRequest {
    wallet_id: u64,
    account_id: U31,
    amount: String,
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StakeAmountRequest {
    wallet_id: u64,
    account_id: U31,
    pledge_amount: String,
    mpt: String,
    cost_per_block: String,
    decommission_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecommissionStakingPoolRequest {
    pub wallet_id: u64,
    pub account_id: U31,
    pub pool_id: String,
    pub output_address: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationCreateRequest {
    pub wallet_id: u64,
    pub account_id: U31,
    pub pool_id: String,
    pub delegation_address: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct StakingDelegateRequest {
    pub wallet_id: u64,
    pub account_id: U31,
    pub delegation_id: DelegationId,
    pub delegation_amount: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewAddressRequest {
    wallet_id: u64,
    account_id: U31,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateEncryptionRequest {
    wallet_id: u64,
    action: String,
    password: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SendDelegateRequest {
    pub wallet_id: u64,
    pub account_id: U31,
    pub address: String,
    pub amount: String,
    pub delegation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewAccountRequest {
    wallet_id: u64,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewAccountResult {
    wallet_id: WalletId,
    account_id: AccountId,
    account_info: AccountInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToggleStakingRequest {
    wallet_id: u64,
    account_id: U31,
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsoleRequest {
    wallet_id: u64,
    account_id: U31,
    command: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToggleStakingResult {
    wallet_id: WalletId,
    account_id: AccountId,
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    tx: SignedTransaction,
    wallet_id: u64,
    account_id: U31,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            initialized_node: RwLock::new(None),
            backend: RwLock::new(None),
        }
    }
}
#[derive(Debug, Clone)]
pub struct InitializedNode {
    pub chain_config: Arc<ChainConfig>,
    pub chain_info: ChainInfo,
}

fn parse_coin_amount(chain_config: &ChainConfig, value: &str) -> Option<Amount> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
}

fn parse_address(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<Address<Destination>, AddressError> {
    Address::from_string(chain_config, address)
}

#[tauri::command]
async fn initialize_node(
    state: tauri::State<'_, AppState>,
    network: &str,
    mode: &str,
) -> Result<ChainInfo, String> {
    let net_type = match network {
        "Mainnet" => InitNetwork::Mainnet,
        "Testnet" => InitNetwork::Testnet,
        _ => return Err("Invalid network selection".into()),
    };
    let wallet_type = match mode {
        "Hot" => WalletMode::Hot,
        "Cold" => WalletMode::Cold,
        _ => return Err("Invalid wallet mode selection".into()),
    };
    let backend_controls = node_initialize(state.clone(), net_type, wallet_type)
        .await
        .map_err(|e| e.to_string())?;
    let mut guard = state.initialized_node.write().await;
    *guard = Some(backend_controls.initialized_node);

    let mut guard_backend = state.backend.write().await;
    *guard_backend = Some(backend_controls.backend);

    if let Some(node) = &*guard {
        Ok(node.chain_info.clone())
    } else {
        Err("backend is not initialized".into())
    }
}
async fn node_initialize(
    _state: tauri::State<'_, AppState>,
    network: InitNetwork,
    mode: WalletMode,
) -> Result<BackendControls, Error> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            "info,wgpu_core=error,hyper=error,jsonrpsee-server=error",
        );
    }

    let mut opts = node_lib::Options::from_args(std::env::args_os());
    opts.command = match network {
        InitNetwork::Mainnet => Some(Command::Mainnet(RunOptions::default())),
        InitNetwork::Testnet => Some(Command::Testnet(RunOptions::default())),
    };

    logging::init_logging();
    logging::log::info!("Command line options: {opts:?}");

    let (low_priority_event_tx, low_priority_event_rx) = unbounded_channel();
    let (wallet_updated_tx, wallet_updated_rx) = unbounded_channel();

    let (chain_config, chain_info, backend) = match mode {
        WalletMode::Hot => {
            let setup_result = node_lib::setup(opts, true).await?;
            let node = match setup_result {
                node_lib::NodeSetupResult::Node(node) => node,
                node_lib::NodeSetupResult::DataDirCleanedUp => {
                    anyhow::bail!(
                        "Data directory is now clean. Please restart the node without `--clean-data` flag"
                    );
                }
            };

            let controller = node.controller().clone();
            tokio::spawn(async move { node.main().await });

            let _chainstate_event_handler =
                ChainstateEventHandler::new(controller.chainstate.clone()).await;
            let _p2p_event_handler = P2pEventHandler::new(&controller.p2p).await;

            let chain_config =
                controller.chainstate.call(|this| Arc::clone(this.get_chain_config())).await?;
            let chain_info = controller.chainstate.call(|this| this.info()).await??;

            let backend = backend_impl::Backend::new_hot(
                Arc::clone(&chain_config),
                low_priority_event_tx,
                wallet_updated_tx,
                controller,
                // manager_join_handle,
            );

            let backend_clone = backend.clone();
            tokio::spawn(async move {
                backend_impl::run(
                    backend,
                    wallet_updated_rx,
                    _chainstate_event_handler,
                    _p2p_event_handler,
                    GLOBAL_APP_HANDLE.clone(),
                )
                .await;
            });

            let backend_arc = Arc::new(backend_clone);
            (chain_config, chain_info, backend_arc)
        }
        WalletMode::Cold => {
            let chain_config = Arc::new(match network {
                InitNetwork::Mainnet => common::chain::config::create_mainnet(),
                InitNetwork::Testnet => common::chain::config::create_testnet(),
            });
            let chain_info = ChainInfo {
                best_block_id: chain_config.genesis_block_id(),
                best_block_height: BlockHeight::zero(),
                median_time: chain_config.genesis_block().timestamp(),
                best_block_timestamp: chain_config.genesis_block().timestamp(),
                is_initial_block_download: false,
            };

            tokio::spawn(async move {});

            let backend = backend_impl::Backend::new_cold(
                Arc::clone(&chain_config),
                low_priority_event_tx,
                wallet_updated_tx,
                // manager_join_handle,
            );

            let backend_clone = backend.clone();

            tokio::spawn(async move {
                backend_impl::run_cold(backend, wallet_updated_rx).await;
            });
            let backend_arc = Arc::new(backend_clone);
            (chain_config, chain_info, backend_arc)
        }
    };
    let initialized_node = InitializedNode {
        chain_config: Arc::clone(&chain_config),
        chain_info,
    };

    let backend_controls = BackendControls {
        initialized_node,
        low_priority_backend_receiver: low_priority_event_rx,
        backend: backend,
    };

    Ok(backend_controls)
}

#[tauri::command]
async fn add_create_wallet_wrapper(
    state: tauri::State<'_, AppState>,
    request: OpenCreateWalletRequest,
) -> Result<WalletInfo, String> {
    let mnemonic = wallet_controller::mnemonic::Mnemonic::parse(request.mnemonic).map_err(|e| {
        let error_message = e.to_string();
        println!("Error parsing mnemonic: {}", error_message);
        error_message
    })?;

    let file_path = PathBuf::from(request.file_path);

    let wallet_type = WalletType::from_str(&request.wallet_type).map_err(|e| {
        let error_message = e.to_string();
        println!("Error parsing wallet type: {}", error_message);
        error_message
    })?;

    let import = ImportOrCreate::from_bool(request.import);

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;

        backend.add_create_wallet(file_path, mnemonic, wallet_type, import).await
    };

    match result {
        Ok(wallet_info) => {
            println!("Wallet created successfully: {:?}", wallet_info);
            Ok(wallet_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error creating wallet: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn add_open_wallet_wrapper(
    state: tauri::State<'_, AppState>,
    request: OpenWalletRequest,
) -> Result<WalletInfo, String> {
    let file_path = PathBuf::from(request.file_path);

    let wallet_type = WalletType::from_str(&request.wallet_type).map_err(|e| {
        let error_message = e.to_string();
        println!("Error parsing wallet type: {}", error_message);
        error_message
    })?;
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.add_open_wallet(file_path, wallet_type).await
    };

    match result {
        Ok(wallet_info) => {
            println!("Wallet created successfully: {:?}", wallet_info);
            Ok(wallet_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error creating wallet: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn send_amount_wrapper(
    state: tauri::State<'_, AppState>,
    request: SendAmountRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;

        let request = SendRequest {
            wallet_id: wallet_id,
            account_id: account_id,
            amount: request.amount,
            address: request.address,
        };

        backend.send_amount(request).await
    };

    match result {
        Ok(transaction_info) => {
            println!("Transaction sent successfully: {:?}", transaction_info);
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending amount: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn new_address_wrapper(
    state: tauri::State<'_, AppState>,
    request: NewAddressRequest,
) -> Result<AddressInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id: AccountId = AccountId::new(request.account_id);

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;

        backend.new_address(wallet_id, account_id).await
    };

    match result {
        Ok(address_info) => {
            println!("Transaction sent successfully: {:?}", address_info);
            Ok(address_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending amount: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn update_encryption_wrapper(
    state: tauri::State<'_, AppState>,
    request: UpdateEncryptionRequest,
) -> Result<(WalletId, EncryptionState), String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let update_encryption_action =
        match EncryptionAction::from_str(&request.action, request.password.as_deref()) {
            Some(action) => action,
            None => return Err("Invalid action or missing password".into()),
        };
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;

        backend.update_encryption(wallet_id, update_encryption_action).await
    };

    match result {
        Ok(address_info) => {
            println!("Transaction sent successfully: {:?}", address_info);
            Ok(address_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending amount: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn close_wallet_wrapper(
    state: tauri::State<'_, AppState>,
    wallet_id: u64,
) -> Result<WalletId, String> {
    let wallet_id = WalletId::from_u64(wallet_id);

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;

        if let Some(wallet) = backend.wallets.remove(&wallet_id) {
            wallet.shutdown().await;
            Ok(())
        } else {
            Err("Wallet not found".into())
        }
    };

    match result {
        Ok(()) => Ok(wallet_id),
        Err(e) => {
            println!("Error closing wallet: {}", e);
            Err(e)
        }
    }
}

#[tauri::command]
async fn stake_amount_wrapper(
    state: tauri::State<'_, AppState>,
    request: StakeAmountRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let stake_request = StakeRequest {
        wallet_id: wallet_id,
        account_id: account_id,
        pledge_amount: request.pledge_amount,
        mpt: request.mpt,
        cost_per_block: request.cost_per_block,
        decommission_address: request.decommission_address,
    };

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.stake_amount(stake_request).await
    };

    match result {
        Ok(transaction_info) => {
            println!("Staked successfully: {:?}", transaction_info);
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error staking amount: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn decommission_pool_wrapper(
    state: tauri::State<'_, AppState>,
    request: DecommissionStakingPoolRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let decommission_request = DecommissionPoolRequest {
        wallet_id: wallet_id,
        account_id: account_id,
        pool_id: request.pool_id,
        output_address: request.output_address,
    };

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.decommission_pool(decommission_request).await
    };

    match result {
        Ok(transaction_info) => {
            println!("Pool decommissioned successfully: {:?}", transaction_info);
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error decommissioning pool: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn create_delegation_wrapper(
    state: tauri::State<'_, AppState>,
    request: DelegationCreateRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let delegation_request = CreateDelegationRequest {
        wallet_id: wallet_id,
        account_id: account_id,
        pool_id: request.pool_id,
        delegation_address: request.delegation_address,
    };

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.create_delegation(delegation_request).await
    };

    match result {
        Ok(transaction_info) => {
            println!("Delegation created successfully: {:?}", transaction_info);
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error creating delegation: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn delegate_staking_wrapper(
    state: tauri::State<'_, AppState>,
    request: StakingDelegateRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let delegation_request = DelegateStakingRequest {
        wallet_id: wallet_id,
        account_id: account_id,
        delegation_id: request.delegation_id,
        delegation_amount: request.delegation_amount,
    };

    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.delegate_staking(delegation_request).await
    };

    match result {
        Ok(transaction_info) => {
            println!("Delegation created successfully: {:?}", transaction_info);
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error creating delegation: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn send_delegation_to_address_wrapper(
    state: tauri::State<'_, AppState>,
    request: SendDelegateRequest,
) -> Result<TransactionInfo, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let send_delegation_request = SendDelegateToAddressRequest {
        wallet_id: wallet_id,
        account_id: account_id,
        address: request.address,
        amount: request.amount,
        delegation_id: request.delegation_id,
    };

    let result: std::result::Result<TransactionInfo, BackendError> = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.send_delegation_to_address(send_delegation_request).await
    };

    match result {
        Ok(transaction_info) => {
            println!(
                "Sending delegation to address completed successfully: {:?}",
                transaction_info
            );
            Ok(transaction_info)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending delegation: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn new_account_wrapper(
    state: tauri::State<'_, AppState>,
    request: NewAccountRequest,
) -> Result<NewAccountResult, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.new_account(wallet_id, request.name).await
    };

    match result {
        Ok(account_info) => {
            println!("Account created successfully: {:?}", account_info);
            Ok(NewAccountResult {
                wallet_id: account_info.0,
                account_id: account_info.1,
                account_info: account_info.2,
            })
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending delegation: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn toggle_stakig_wrapper(
    state: tauri::State<'_, AppState>,
    request: ToggleStakingRequest,
) -> Result<ToggleStakingResult, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.toggle_staking(wallet_id, account_id, request.enabled).await
    };

    match result {
        Ok(account_info) => {
            println!("Account created successfully: {:?}", account_info);
            Ok(ToggleStakingResult {
                wallet_id: account_info.0,
                account_id: account_info.1,
                enabled: account_info.2,
            })
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error sending delegation: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn handle_console_command_wrapper(
    state: tauri::State<'_, AppState>,
    request: ConsoleRequest,
) -> Result<ConsoleCommand, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let account_id = AccountId::new(request.account_id);
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.handle_console_command(wallet_id, account_id, request.command).await
    };

    match result {
        Ok(command) => {
            println!("Console command executed successfully: {:?}", command);
            Ok(command)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error executing console command: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn submit_transaction_wrapper(
    state: tauri::State<'_, AppState>,
    request: SubmitTransactionRequest,
) -> Result<backend_impl::SubmitTransactionResult, String> {
    let wallet_id = WalletId::from_u64(request.wallet_id);
    let result = {
        let mut backend_guard = state.backend.write().await;
        let backend_arc = backend_guard.as_mut().ok_or("Backend not initialized")?;
        let backend = Arc::get_mut(backend_arc).ok_or("Cannot get mutable reference")?;
        backend.submit_transaction(wallet_id, request.account_id, request.tx).await
    };

    match result {
        Ok(command) => {
            println!("Transaction submitted successfully: {:?}", command);
            Ok(command)
        }
        Err(e) => {
            let error_message = e.to_string();
            println!("Error submitting transaction: {}", error_message);
            Err(error_message)
        }
    }
}

#[tauri::command]
async fn shutdown_wrapper(state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Lock the backend state and get a mutable reference
    let mut backend_guard = state.backend.write().await;

    // Check if the backend is initialized and get a mutable reference
    let backend_arc =
        backend_guard.as_mut().ok_or_else(|| "Backend not initialized".to_string())?;

    // Attempt to get a mutable reference to the backend
    let backend =
        Arc::get_mut(backend_arc).ok_or_else(|| "Cannot get mutable reference".to_string())?;

    // Await the shutdown operation
    <backend_impl::Backend as Clone>::clone(&backend).shutdown().await;

    // If everything succeeded, return Ok
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // get_initialized_node,
            initialize_node,
            add_create_wallet_wrapper,
            add_open_wallet_wrapper,
            send_amount_wrapper,
            new_address_wrapper,
            update_encryption_wrapper,
            close_wallet_wrapper,
            stake_amount_wrapper,
            decommission_pool_wrapper,
            create_delegation_wrapper,
            delegate_staking_wrapper,
            send_delegation_to_address_wrapper,
            new_account_wrapper,
            toggle_stakig_wrapper,
            handle_console_command_wrapper,
            submit_transaction_wrapper,
            shutdown_wrapper
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app_handle, event| match event {
            tauri::RunEvent::Ready => {
                println!("Window loaded");
                GLOBAL_APP_HANDLE
                    .set(_app_handle.clone())
                    .expect("Failed to set global app handle");
            }
            _ => {}
        });
}
