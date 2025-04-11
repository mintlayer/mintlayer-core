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

pub mod account;
pub mod destination_getters;
pub mod key_chain;
pub mod send_request;
pub mod signer;
pub mod version;
pub mod wallet;
pub mod wallet_events;

use signer::software_signer::SoftwareSignerProvider;

pub use crate::account::Account;
pub use crate::send_request::SendRequest;
pub use crate::wallet::{Wallet, WalletError, WalletResult};

pub type DefaultWallet = Wallet<wallet_storage::DefaultBackend, SoftwareSignerProvider>;
