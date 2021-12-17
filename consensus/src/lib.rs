// use blockchain_storage::BlockchainStorage;
// use common::chain::config::ChainConfig;
// use common::chain::block::Block;

mod chain_state;

mod orphan_blocks;
// use orphan_blocks::OrphanBlocks;

// struct Consensus<S: BlockchainStorage> {
//     chain_config: ChainConfig,
//     blockchain_storage: S,
//     orphan_blocks: OrphanBlocks,
// }

// impl<S: BlockchainStorage> Consensus<S> {
//     pub fn process_block(block: Block) {

//     }
// }

#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
