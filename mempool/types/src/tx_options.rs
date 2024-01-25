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

/// Transaction priority for block inclusion and mempool eviction
#[derive(
    Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize,
)]
pub enum TxPriority {
    Normal,
    High,
}

/// Options specifying how should a transaction be handled by mempool and p2p.
// Can be extended further with custom eviction policies, tx orphan pool policies, etc.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TxOptions {
    /// What checks to apply to the transaction
    trust_policy: TxTrustPolicy,

    /// Whether the transaction should be relayed
    relay_policy: TxRelayPolicy,

    /// Priority for including the transaction in the block and evicting it from the mempool.
    /// Overrides the usual feerate-based priority.
    priority: TxPriority,
}

impl TxOptions {
    /// Default options for given transaction origin
    pub const fn default_for(origin: TxOrigin) -> Self {
        let trust_policy = TxTrustPolicy::Untrusted;
        let priority = TxPriority::Normal;

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
            priority,
        }
    }

    /// Apply given user-specified overrides to the options
    pub const fn with_overrides(mut self, overrides: TxOptionsOverrides) -> Self {
        let TxOptionsOverrides {
            trust_policy,
            priority,
        } = overrides;

        if let Some(trust_policy) = trust_policy {
            self.trust_policy = trust_policy;
        }

        if let Some(priority) = priority {
            self.priority = priority;
        }

        self
    }

    pub fn trust_policy(&self) -> TxTrustPolicy {
        self.trust_policy
    }

    pub fn relay_policy(&self) -> TxRelayPolicy {
        self.relay_policy
    }

    pub fn priority(&self) -> TxPriority {
        self.priority
    }
}

/// Mechanism to apply user-specified overrides to [TxOptions].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct TxOptionsOverrides {
    /// Override transaction trust policy.
    trust_policy: Option<TxTrustPolicy>,

    /// Override transaction priority
    priority: Option<TxPriority>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn priority_ord_correct() {
        assert!(TxPriority::Normal < TxPriority::High);
    }
}
