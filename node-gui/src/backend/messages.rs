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

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use chainstate::ChainInfo;
use common::{
    address::Address,
    chain::{DelegationId, Destination, GenBlock, PoolId, SignedTransaction},
    primitives::{Amount, BlockHeight, Id},
};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};
use p2p::P2pEvent;
use wallet::account::{currency_grouper::Currency, transaction_list::TransactionList, PoolData};

use crate::main_window::ImportOrCreate;

use super::BackendError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletId(u64);

static NEXT_WALLET_ID: AtomicU64 = AtomicU64::new(0);

impl WalletId {
    pub fn new() -> Self {
        Self(NEXT_WALLET_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountId(U31);

impl AccountId {
    pub fn new(index: U31) -> Self {
        Self(index)
    }

    pub fn account_index(&self) -> U31 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub wallet_id: WalletId,
    pub path: PathBuf,
    pub encryption: EncryptionState,
    pub accounts: BTreeMap<AccountId, AccountInfo>,
    pub best_block: (Id<GenBlock>, BlockHeight),
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub name: Option<String>,
    pub addresses: BTreeMap<ChildNumber, Address<Destination>>,
    pub staking_enabled: bool,
    pub balance: BTreeMap<Currency, Amount>,
    pub staking_balance: BTreeMap<PoolId, (PoolData, Amount)>,
    pub delegations_balance: BTreeMap<DelegationId, (PoolId, Amount)>,
    pub transaction_list: TransactionList,
}

#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub index: ChildNumber,
    pub address: Address<Destination>,
}

#[derive(Debug, Clone)]
pub struct SendRequest {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub address: String,
    pub amount: String,
}

#[derive(Debug, Clone)]
pub struct StakeRequest {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub pledge_amount: String,
    pub mpt: String,
    pub cost_per_block: String,
    pub decommission_address: String,
}

#[derive(Debug, Clone)]
pub struct CreateDelegationRequest {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub pool_id: String,
    pub delegation_address: String,
}

#[derive(Debug, Clone)]
pub struct DelegateStakingRequest {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub delegation_id: DelegationId,
    pub delegation_amount: String,
}

#[derive(Debug, Clone)]
pub struct SendDelegateToAddressRequest {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub address: String,
    pub amount: String,
    pub delegation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInfo {
    pub wallet_id: WalletId,
    pub tx: SignedTransaction,
}

#[derive(Debug)]
pub enum EncryptionAction {
    SetPassword(String),
    RemovePassword,
    Unlock(String),
    Lock,
}

#[derive(Debug, Clone)]
pub enum EncryptionState {
    EnabledLocked,
    EnabledUnlocked,
    Disabled,
}

#[derive(Debug)]
pub enum BackendRequest {
    OpenWallet {
        file_path: PathBuf,
    },
    // This will remove the old file if it already exists.
    // The frontend should check if this is what the user really wants.
    RecoverWallet {
        mnemonic: wallet_controller::mnemonic::Mnemonic,
        file_path: PathBuf,
        import: ImportOrCreate,
    },
    CloseWallet(WalletId),

    UpdateEncryption {
        wallet_id: WalletId,
        action: EncryptionAction,
    },

    NewAccount {
        wallet_id: WalletId,

        /// New account name (will be trimmed first and if empty, no name will be used
        /// because the wallet controller does not allow empty names)
        name: String,
    },

    NewAddress(WalletId, AccountId),
    ToggleStaking(WalletId, AccountId, bool),
    SendAmount(SendRequest),
    StakeAmount(StakeRequest),
    CreateDelegation(CreateDelegationRequest),
    DelegateStaking(DelegateStakingRequest),
    SendDelegationToAddress(SendDelegateToAddressRequest),

    SubmitTx {
        wallet_id: WalletId,
        tx: SignedTransaction,
    },

    TransactionList {
        wallet_id: WalletId,
        account_id: AccountId,
        skip: usize,
    },

    Shutdown,
}

#[derive(Debug, Clone)]
pub enum BackendEvent {
    ChainInfo(ChainInfo),
    P2p(P2pEvent),

    OpenWallet(Result<WalletInfo, BackendError>),
    ImportWallet(Result<WalletInfo, BackendError>),
    CloseWallet(WalletId),

    UpdateEncryption(Result<(WalletId, EncryptionState), BackendError>),

    NewAccount(Result<(WalletId, AccountId, AccountInfo), BackendError>),

    WalletBestBlock(WalletId, (Id<GenBlock>, BlockHeight)),
    Balance(WalletId, AccountId, BTreeMap<Currency, Amount>),
    StakingBalance(WalletId, AccountId, BTreeMap<PoolId, (PoolData, Amount)>),
    DelegationsBalance(
        WalletId,
        AccountId,
        BTreeMap<DelegationId, (PoolId, Amount)>,
    ),
    NewAddress(Result<AddressInfo, BackendError>),
    ToggleStaking(Result<(WalletId, AccountId, bool), BackendError>),
    SendAmount(Result<TransactionInfo, BackendError>),
    StakeAmount(Result<TransactionInfo, BackendError>),
    CreateDelegation(Result<TransactionInfo, BackendError>),
    DelegateStaking(Result<(TransactionInfo, DelegationId), BackendError>),
    SendDelegationToAddress(Result<TransactionInfo, BackendError>),
    Broadcast(Result<WalletId, BackendError>),

    TransactionList(WalletId, AccountId, Result<TransactionList, BackendError>),
}
