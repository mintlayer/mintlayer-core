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

use std::borrow::Cow;

use crypto::key::hdkd::u31::U31;
use reedline::{Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus};
use wallet_controller::DEFAULT_ACCOUNT_INDEX;

use crate::errors::WalletCliError;

/// A very simple [Prompt] trait implementation
/// ([reedline::DefaultPrompt] shows the current dir and the clock on the right, which we don't need)
#[derive(Clone)]
pub struct WalletPrompt {
    prompt_left: String,
    selected_account: Option<(U31, usize)>,
}

impl WalletPrompt {
    pub fn new() -> Self {
        WalletPrompt {
            prompt_left: "Wallet".into(),
            selected_account: None,
        }
    }

    fn update_status(&mut self) {
        if let Some((selected_account, total_accounts)) = self.selected_account {
            self.prompt_left = format!("Wallet: ({}/{})", selected_account, total_accounts)
        } else {
            self.prompt_left = "Wallet".into()
        }
    }

    pub fn set_total_accounts(&mut self, new_total_accounts: usize) {
        if new_total_accounts == 0 {
            self.selected_account = None;
        } else if let Some((_, total_accounts)) = self.selected_account.as_mut() {
            *total_accounts = new_total_accounts;
        } else {
            self.selected_account.replace((DEFAULT_ACCOUNT_INDEX, new_total_accounts));
        }

        self.update_status();
    }

    pub fn set_selected_account(&mut self, account_index: U31) -> Result<(), WalletCliError> {
        let (selected_account, total_accounts) =
            self.selected_account.as_mut().ok_or(WalletCliError::NoWallet)?;

        if selected_account.into_u32() as usize >= *total_accounts {
            return Err(WalletCliError::AccountNotFound(account_index));
        }

        *selected_account = account_index;
        self.update_status();
        Ok(())
    }

    pub fn selected_account(&self) -> Option<U31> {
        self.selected_account.as_ref().map(|(selected_account, _)| *selected_account)
    }
}

impl Prompt for WalletPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        Cow::Borrowed(self.prompt_left.as_str())
    }

    fn render_prompt_right(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}
