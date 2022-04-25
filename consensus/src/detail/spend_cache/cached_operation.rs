use common::chain::{Spender, TxMainChainIndex};

use crate::detail::BlockError;

pub enum CachedInputsOperation {
    Write(TxMainChainIndex),
    Read(TxMainChainIndex),
    Erase,
}

impl CachedInputsOperation {
    pub fn spend(&mut self, output_index: u32, spender: Spender) -> Result<(), BlockError> {
        // spend the output
        match self {
            CachedInputsOperation::Write(tx_index) | CachedInputsOperation::Read(tx_index) => {
                tx_index.spend(output_index, spender).map_err(BlockError::from)?
            }
            CachedInputsOperation::Erase => {
                return Err(BlockError::MissingOutputOrSpentOutputErased)
            }
        }

        self.mark_as_write();

        Ok(())
    }

    pub fn unspend(&mut self, output_index: u32) -> Result<(), BlockError> {
        // unspend the output
        match self {
            CachedInputsOperation::Write(tx_index) | CachedInputsOperation::Read(tx_index) => {
                tx_index.unspend(output_index).map_err(BlockError::from)?
            }
            CachedInputsOperation::Erase => {
                return Err(BlockError::MissingOutputOrSpentOutputErased)
            }
        }

        self.mark_as_write();

        Ok(())
    }

    fn mark_as_write(&mut self) {
        // replace &mut self with a new value (must be done like this because it's unsafe)
        let replacer_func = |self_| match self_ {
            CachedInputsOperation::Write(tx_index) => CachedInputsOperation::Write(tx_index),
            CachedInputsOperation::Read(tx_index) => CachedInputsOperation::Write(tx_index),
            CachedInputsOperation::Erase => unreachable!(),
        };
        replace_with::replace_with_or_abort(self, replacer_func);
    }
}

// TODO: tests
