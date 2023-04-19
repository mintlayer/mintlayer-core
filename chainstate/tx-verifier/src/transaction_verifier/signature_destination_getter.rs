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

use common::chain::{Destination, PoolId, TxOutput};
use pos_accounting::PoSAccountingView;

use super::accounting_delta_adapter::PoSAccountingDeltaAdapter;

pub type SignatureDestinationGetterFn<'a> =
    dyn Fn(&TxOutput) -> Result<Destination, SignatureDestinationGetterError> + 'a;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum SignatureDestinationGetterError {
    #[error("Attempted to spend output in block reward")]
    SpendingOutputInBlockReward,
    #[error("Attempted to verify signature for burning output")]
    SigVerifyOfBurnedOutput,
    #[error("Pool data not found for signature verification {0}")]
    PoolDataNotFound(PoolId),
    #[error("During destination getting for signature verification: PoS accounting error {0}")]
    SigVerifyPoSAccountingError(#[from] pos_accounting::Error),
}

/// Given a signed transaction input, which spends an output of some type,
/// what is the destination of the output being spent, against which
/// signatures should be verified?
///
/// Generally speaking, there's no way to know. Hence, we create generic way
/// to do this. At the time of creating this struct, it was simple and mapping
/// from output type to destination was trivial, and only required distinguishing
/// between block reward and transaction outputs. In the future, this struct is
/// supposed to be extended to support more complex cases, where the caller can
/// request the correct mapping from output type to destination for signature
/// verification.
///
/// The errors returned in the functions based on the output type are generally
/// checked in other places, but this is just double-checking and ensuring sanity,
/// since there's close to zero harm doing it right anyway (e.g., pulling in more
/// dependencies).
pub struct SignatureDestinationGetter<'a> {
    f: Box<SignatureDestinationGetterFn<'a>>,
}

impl<'a> SignatureDestinationGetter<'a> {
    pub fn new_for_transaction<P: PoSAccountingView>(
        accounting_delta: &'a PoSAccountingDeltaAdapter<P>,
    ) -> Self {
        let destination_getter =
            |output: &TxOutput| -> Result<Destination, SignatureDestinationGetterError> {
                match output {
                    TxOutput::Transfer(_, d)
                    | TxOutput::LockThenTransfer(_, d, _)
                    | TxOutput::DelegateStaking(_, d, _)
                    | TxOutput::SpendShareFromDelegation(_, d, _)
                    | TxOutput::DecommissionPool(_, d, _, _) => Ok(d.clone()),
                    TxOutput::CreateDelegationId(_, _) | TxOutput::Burn(_) => {
                        // This error is emitted in other places for attempting to make this spend,
                        // but this is just a double-check.
                        Err(SignatureDestinationGetterError::SigVerifyOfBurnedOutput)
                    }
                    TxOutput::CreateStakePool(pool_data) => {
                        // Spending an output of a pool creation transaction is only allowed in a
                        // context of a transaction (as opposed to block reward) only if this pool
                        // is being decommissioned.
                        // If this rule is being invalidated, it will be detected in other parts
                        // of the code.
                        Ok(pool_data.decommission_key().clone())
                    }
                    TxOutput::ProduceBlockFromStake(_, pool_id) => {
                        // The only way we can spend this output in a transaction
                        // (as opposed to block reward), is if we're decommissioning a pool.
                        Ok(accounting_delta
                            .accounting_delta()
                            .get_pool_data(*pool_id)?
                            .ok_or(SignatureDestinationGetterError::PoolDataNotFound(*pool_id))?
                            .decommission_destination()
                            .clone())
                    }
                }
            };

        Self {
            f: Box::new(destination_getter),
        }
    }

    pub fn new_for_block_reward() -> Self {
        let destination_getter =
            |output: &TxOutput| -> Result<Destination, SignatureDestinationGetterError> {
                match output {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::DelegateStaking(_, _, _)
                    | TxOutput::SpendShareFromDelegation(_, _, _)
                    | TxOutput::DecommissionPool(_, _, _, _) => {
                        Err(SignatureDestinationGetterError::SpendingOutputInBlockReward)
                    }
                    TxOutput::CreateDelegationId(_, _) | TxOutput::Burn(_) => {
                        Err(SignatureDestinationGetterError::SigVerifyOfBurnedOutput)
                    }

                    TxOutput::ProduceBlockFromStake(d, _) => {
                        // Spending an output of a block creation output is only allowed to
                        // create another block, given that this is a block reward.
                        Ok(d.clone())
                    }
                    TxOutput::CreateStakePool(pool_data) => {
                        // Spending an output of a pool creation output is only allowed when
                        // creating a block (given it's in a block reward; otherwise it should
                        // be a transaction for decommissioning the pool), hence the staker key
                        // is checked.
                        Ok(pool_data.staker().clone())
                    }
                }
            };

        Self {
            f: Box::new(destination_getter),
        }
    }

    #[allow(dead_code)]
    pub fn new_custom(f: Box<SignatureDestinationGetterFn<'a>>) -> Self {
        Self { f }
    }

    pub fn call(&self, output: &TxOutput) -> Result<Destination, SignatureDestinationGetterError> {
        (self.f)(output)
    }
}

// TODO: tests
