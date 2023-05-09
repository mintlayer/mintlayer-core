use common::chain::{Destination, TxOutput};
use pos_accounting::PoSAccountingView;

use crate::error::ConnectTransactionError;

use super::accounting_delta_adapter::PoSAccountingDeltaAdapter;

pub type SignatureDestinationGetterFn<'a> =
    dyn Fn(&TxOutput) -> Result<Destination, ConnectTransactionError> + 'a;

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
pub struct SignatureDestinationGetter<'a> {
    f: Box<SignatureDestinationGetterFn<'a>>,
}

impl<'a> SignatureDestinationGetter<'a> {
    pub fn new_for_transaction<P: PoSAccountingView>(
        accounting_delta: &'a PoSAccountingDeltaAdapter<P>,
    ) -> Self {
        let destination_getter =
            |output: &TxOutput| -> Result<Destination, ConnectTransactionError> {
                match output {
                    TxOutput::Transfer(_, d)
                    | TxOutput::LockThenTransfer(_, d, _)
                    | TxOutput::DecommissionPool(_, d, _, _) => Ok(d.clone()),
                    TxOutput::Burn(_) => Err(ConnectTransactionError::AttemptToSpendBurnedAmount),
                    TxOutput::CreateStakePool(pool_data) => {
                        // Spending an output of a pool creation transaction is only allowed in a
                        // context of a transaction (as opposed to block reward) only if this pool
                        // is being decommissioned.
                        // If this rule is being invalidated, it will be detected in other parts
                        // of the code.
                        Ok(pool_data.decommission_key().clone())
                    }
                    TxOutput::ProduceBlockFromStake(_, pool_id) => Ok(accounting_delta
                        .accounting_delta()
                        .get_pool_data(*pool_id)?
                        .ok_or(ConnectTransactionError::PoolDataNotFound(*pool_id))?
                        .decommission_destination()
                        .clone()),
                }
            };

        Self {
            f: Box::new(destination_getter),
        }
    }

    pub fn new_for_block_reward() -> Self {
        let destination_getter =
            |output: &TxOutput| -> Result<Destination, ConnectTransactionError> {
                match output {
                    TxOutput::Transfer(_, d)
                    | TxOutput::LockThenTransfer(_, d, _)
                    | TxOutput::DecommissionPool(_, d, _, _)
                    | TxOutput::ProduceBlockFromStake(d, _) => Ok(d.clone()),
                    TxOutput::Burn(_) => Err(ConnectTransactionError::AttemptToSpendBurnedAmount),
                    TxOutput::CreateStakePool(pool_data) => {
                        // Spending an output of a pool creation transaction is only allowed when
                        // creating a block, hence the staker key is checked.
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

    pub fn call(&self, output: &TxOutput) -> Result<Destination, ConnectTransactionError> {
        (self.f)(output)
    }
}

// TODO: tests
