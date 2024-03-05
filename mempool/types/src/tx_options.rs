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

use crate::tx_origin::{LocalTxOrigin, TxOrigin};
use rpc_description::ValueHint as VH;

#[derive(Clone, Copy, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize, Default)]
pub enum TxTrustPolicy {
    /// Mempool policy checks are bypassed for this transaction
    Trusted,

    /// Transaction is subject to all the usual mempool policy checks.
    #[default]
    Untrusted,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum TxRelayPolicy {
    /// Transaction should be relayed by p2p if checks pass
    DoRelay,

    /// Transaction should not be relayed to peers, keeping it local
    DontRelay,
}

/// Options specifying how should a transaction be handled by mempool and p2p.
// Can be extended further with custom eviction policies, tx orphan pool policies, etc.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TxOptions {
    /// What checks to apply to the transaction
    trust_policy: TxTrustPolicy,

    /// Whether the transaction should be relayed
    relay_policy: TxRelayPolicy,
}

impl TxOptions {
    /// Default options for given transaction origin
    pub const fn default_for(origin: TxOrigin) -> Self {
        let trust_policy = TxTrustPolicy::Untrusted;

        let relay_policy = match origin {
            TxOrigin::Local(origin) => match origin {
                LocalTxOrigin::Mempool => TxRelayPolicy::DontRelay,
                LocalTxOrigin::P2p => TxRelayPolicy::DoRelay,
                LocalTxOrigin::PastBlock => TxRelayPolicy::DontRelay,
            },
            TxOrigin::Remote(_) => TxRelayPolicy::DoRelay,
        };

        TxOptions {
            trust_policy,
            relay_policy,
        }
    }

    /// Apply given user-specified overrides to the options
    pub const fn with_overrides(mut self, overrides: TxOptionsOverrides) -> Self {
        if let Some(trust_policy) = overrides.trust_policy {
            self.trust_policy = trust_policy;
        }

        self
    }

    pub fn trust_policy(&self) -> TxTrustPolicy {
        self.trust_policy
    }

    pub fn relay_policy(&self) -> TxRelayPolicy {
        self.relay_policy
    }
}

/// Mechanism to apply user-specified overrides to [TxOptions].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct TxOptionsOverrides {
    /// Override transaction trust policy.
    trust_policy: Option<TxTrustPolicy>,
}

impl rpc_description::HasValueHint for TxOptionsOverrides {
    const HINT: VH = VH::Object(&[(
        "trust_policy",
        &VH::Choice(&[&VH::StrLit("Trusted"), &VH::StrLit("Untrusted")]),
    )]);
}
