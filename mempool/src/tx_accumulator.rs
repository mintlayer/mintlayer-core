use common::{chain::signed_transaction::SignedTransaction, primitives::Amount};
use serialization::Encode;

#[derive(thiserror::Error, Debug, Clone)]
pub enum TxAccumulatorError {
    #[error("Fee overflow: {0:?} + {1:?} failed")]
    FeeAccumulationError(Amount, Amount),
}

pub trait TransactionAccumulator {
    /// Add a transaction to the accumulator and its fee
    /// This method should not mutate self unless it's successful
    /// Meaning: If this call returns an error, the callee should guarantee that &self never changed
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Amount) -> Result<(), TxAccumulatorError>;
    fn done(&self) -> bool;
    fn txs(&self) -> Vec<SignedTransaction>;
    fn total_fee(&self) -> Amount;
}

pub struct DefaultTxAccumulator {
    txs: Vec<SignedTransaction>,
    total_size: usize,
    target_size: usize,
    done: bool,
    total_fee: Amount,
}

impl DefaultTxAccumulator {
    pub fn new(target_size: usize) -> Self {
        Self {
            txs: Vec::new(),
            total_size: 0,
            target_size,
            done: false,
            total_fee: Amount::ZERO,
        }
    }
}

impl TransactionAccumulator for DefaultTxAccumulator {
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Amount) -> Result<(), TxAccumulatorError> {
        if self.total_size + tx.encoded_size() <= self.target_size {
            self.total_size += tx.encoded_size();
            self.total_fee = (self.total_fee + tx_fee)
                .ok_or_else(|| TxAccumulatorError::FeeAccumulationError(self.total_fee, tx_fee))?;
            self.txs.push(tx);
        } else {
            self.done = true
        };
        Ok(())
    }

    fn done(&self) -> bool {
        self.done
    }

    fn txs(&self) -> Vec<SignedTransaction> {
        self.txs.clone()
    }

    fn total_fee(&self) -> Amount {
        self.total_fee
    }
}
