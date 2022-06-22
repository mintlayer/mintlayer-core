use super::Block;
use crate::chain::TransactionSize;
use parity_scale_codec::Encode;

pub struct BlockSize {
    header: usize,
    from_txs: usize,
    from_smart_contracts: usize,
}

impl BlockSize {
    pub fn new_from_block(block: &Block) -> Self {
        block.transactions().iter().map(|tx| tx.transaction_data_size()).fold(
            BlockSize::new_with_header_size(block.header().encoded_size()),
            |mut total, curr| {
                match curr {
                    TransactionSize::ScriptedTransaction(size) => total.from_txs += size,
                    TransactionSize::SmartContractTransaction(size) => {
                        total.from_smart_contracts += size
                    }
                };
                total
            },
        )
    }

    fn new_with_header_size(header_size: usize) -> Self {
        BlockSize {
            header: header_size,
            from_txs: 0,
            from_smart_contracts: 0,
        }
    }

    pub fn size_from_txs(&self) -> usize {
        self.from_txs
    }

    pub fn size_from_smart_contracts(&self) -> usize {
        self.from_smart_contracts
    }

    pub fn size_from_header(&self) -> usize {
        self.header
    }
}

// TODO: write tests
