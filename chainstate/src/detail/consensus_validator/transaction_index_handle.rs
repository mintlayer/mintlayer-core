use common::chain::{OutPointSourceId, Transaction, TxMainChainIndex, TxMainChainPosition};

use crate::detail::PropertyQueryError;

pub trait TransactionIndexHandle {
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, PropertyQueryError>;

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> Result<Option<Transaction>, PropertyQueryError>;
}
