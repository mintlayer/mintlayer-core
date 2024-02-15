// Copyright (c) 2024 RBB S.r.l
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

use common::primitives::H256;
use crypto::key::hdkd::u31::U31;
use node_comm::node_traits::NodeInterface;
use wallet_rpc_client::wallet_rpc_traits::WalletInterface;
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;

use crate::errors::WalletCliError;

pub struct CliWalletState {
    wallet_id: H256,
    account_names: Vec<Option<String>>,
    selected_account: U31,
}

impl CliWalletState {
    pub fn num_accounts(&self) -> usize {
        self.account_names.len()
    }

    pub fn get_selected_acc_name(&self) -> Option<&Option<String>> {
        self.account_names.get(self.selected_account.into_u32() as usize)
    }

    pub fn selected_account(&self) -> U31 {
        self.selected_account
    }

    pub fn set_selected_account(&mut self, selected_account: U31) {
        self.selected_account = selected_account
    }
}

/// This struct ensures we keep the local state in sync with the state of the wallet we are
/// connected to, as it can change through another interface like RPC communication
pub struct WalletWithState<W> {
    // the CliWalletState if there is a loaded wallet
    state: Option<CliWalletState>,
    wallet: W,
}

impl<W, E> WalletWithState<W>
where
    W: WalletInterface<Error = E> + Send + Sync + 'static,
{
    pub async fn new(wallet: W) -> Self {
        let state = Self::fetch_wallet_state(&wallet).await;
        Self { state, wallet }
    }

    async fn fetch_wallet_state(wallet: &W) -> Option<CliWalletState> {
        match wallet.wallet_info().await {
            Ok(info) => Some(CliWalletState {
                wallet_id: info.wallet_id,
                account_names: info.account_names,
                selected_account: DEFAULT_ACCOUNT_INDEX,
            }),
            Err(_) => None,
        }
    }

    pub async fn rpc_completed(&self) {
        self.wallet.rpc_completed().await
    }

    pub async fn get_wallet_with_acc<N: NodeInterface>(
        &mut self,
    ) -> Result<(&W, U31), WalletCliError<N>> {
        let state = Self::update_state(&mut self.state, &self.wallet)
            .await?
            .as_ref()
            .ok_or(WalletCliError::NoWallet)?;
        Ok((&self.wallet, state.selected_account))
    }

    pub async fn get_wallet<N: NodeInterface>(&mut self) -> Result<&W, WalletCliError<N>> {
        Self::update_state(&mut self.state, &self.wallet).await?;
        Ok(&self.wallet)
    }

    pub async fn get_wallet_mut<N: NodeInterface>(&mut self) -> Result<&mut W, WalletCliError<N>> {
        Self::update_state(&mut self.state, &self.wallet).await?;
        Ok(&mut self.wallet)
    }

    pub async fn get_mut_state<N: NodeInterface>(
        &mut self,
    ) -> Result<&mut CliWalletState, WalletCliError<N>> {
        Self::update_state(&mut self.state, &self.wallet)
            .await?
            .as_mut()
            .ok_or(WalletCliError::NoWallet)
    }

    pub async fn get_opt_state<N: NodeInterface>(
        &mut self,
    ) -> Result<&Option<CliWalletState>, WalletCliError<N>> {
        Self::update_state(&mut self.state, &self.wallet).await.map(|state| &*state)
    }

    pub async fn update_wallet<N: NodeInterface>(&mut self) {
        let _ = Self::update_state::<N>(&mut self.state, &self.wallet).await;
    }

    async fn update_state<'a, N: NodeInterface>(
        local_state: &'a mut Option<CliWalletState>,
        wallet: &W,
    ) -> Result<&'a mut Option<CliWalletState>, WalletCliError<N>> {
        match (local_state.as_mut(), Self::fetch_wallet_state(wallet).await) {
            (None, Some(rpc_state)) => {
                *local_state = Some(rpc_state);
                Err(WalletCliError::NewWalletWasOpened)
            }
            (Some(state), Some(rpc_state)) => {
                if state.wallet_id != rpc_state.wallet_id {
                    *local_state = Some(rpc_state);
                    Err(WalletCliError::DifferentWalletWasOpened)
                } else {
                    state.account_names = rpc_state.account_names;
                    Ok(local_state)
                }
            }
            (Some(_), None) => {
                *local_state = None;
                Err(WalletCliError::ExistingWalletWasClosed)
            }
            (None, None) => Ok(local_state),
        }
    }
}
