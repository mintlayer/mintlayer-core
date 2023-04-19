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

use dialoguer::theme::ColorfulTheme;

use crate::errors::WalletCliError;

pub fn select_helper<T: Clone + Into<&'static str>>(
    theme: &ColorfulTheme,
    prompt: &str,
    items: &[T],
) -> Result<T, WalletCliError> {
    let texts = items.iter().cloned().map(Into::into).collect::<Vec<&str>>();
    let index = dialoguer::Select::with_theme(theme)
        .with_prompt(prompt)
        .default(0)
        .items(&texts)
        .interact_opt()
        .map_err(WalletCliError::ConsoleIoError)?
        .ok_or(WalletCliError::Cancelled)?;
    Ok(items[index].clone())
}
