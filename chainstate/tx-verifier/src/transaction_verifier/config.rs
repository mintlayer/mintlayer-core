// Copyright (c) 2022 RBB S.r.l
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

#[derive(Clone)]
pub struct TransactionVerifierConfig {
    pub tx_index_enabled: bool,
}

impl TransactionVerifierConfig {
    pub fn new(tx_index_enabled: bool) -> Self {
        Self { tx_index_enabled }
    }

    /// If transaction index is enabled, the function f is called, otherwise Ok(None) is returned
    /// This function returns `Result<Option<T>, E>` instead of `Option<Result<T,E>>` for convenience,
    /// since error handling should happen before knowing the result
    pub fn if_tx_index_enabled<F, T, E>(&self, f: F) -> Result<Option<T>, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        self.tx_index_enabled.then(f).transpose()
    }
}
