use chainstate::chainstate_interface::ChainstateInterface;
use chainstate_test_framework::TestFramework;
use common::chain::Block;
use common::primitives::Id;
use common::primitives::Idable;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

/// Ensure that the blocks vector put blocks in order with height in the blockchain
fn check_height_order<C: ChainstateInterface>(blocks: &Vec<Id<Block>>, chainstate: &C) {
    let mut last_height = 0;
    for block_id in blocks {
        let height = chainstate
            .get_block_height_in_main_chain(&block_id.get().into())
            .expect("Database error")
            .expect("We loaded this from chainstate");
        let current_height: u64 = height.into();
        assert!(current_height >= last_height);
        last_height = current_height;
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_simple(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();
        let genesis_id = tf.genesis().get_id();

        let chain1 = {
            tf.create_chain(&genesis_id.into(), 5, &mut rng).unwrap();

            let _last_block_id = tf.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since there's only one chain, both should be equal
            assert_eq!(mainchain_vec, tree_vec);
            assert_eq!(mainchain_vec.len(), 5);

            check_height_order(&mainchain_vec, &tf.chainstate);
            check_height_order(&tree_vec, &tf.chainstate);

            mainchain_vec
        };

        let chain2 = {
            tf.create_chain(&genesis_id.into(), 15, &mut rng).unwrap();

            let _last_block_id = tf.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 15);
            assert_eq!(tree_vec.len(), 20);

            check_height_order(&mainchain_vec, &tf.chainstate);
            check_height_order(&tree_vec, &tf.chainstate);

            mainchain_vec
        };

        let chain3 = {
            tf.create_chain(&genesis_id.into(), 25, &mut rng).unwrap();

            let _last_block_id = tf.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(mainchain_vec.len(), 25);
            assert_eq!(tree_vec.len(), 45);

            check_height_order(&mainchain_vec, &tf.chainstate);
            check_height_order(&tree_vec, &tf.chainstate);

            mainchain_vec
        };

        let _chain4 = {
            let len_to_cut_from_branch = 5;
            let new_branch_len = 35;
            tf.create_chain(
                &chain2[chain2.len() - 1 - len_to_cut_from_branch].get().into(),
                new_branch_len,
                &mut rng,
            )
            .unwrap();

            let _last_block_id = tf.chainstate.get_block_id_tree_as_list().unwrap();

            let tree_vec = tf.chainstate.get_block_id_tree_as_list().unwrap();
            let mainchain_vec = tf.chainstate.get_mainchain_blocks_list().unwrap();

            // since now we have orphans, we have to ensure that all blocks exist
            assert!(mainchain_vec.iter().all(|item| tree_vec.contains(item)));
            assert!(chain1.iter().all(|item| tree_vec.contains(item)));
            assert!(chain2.iter().all(|item| tree_vec.contains(item)));
            assert!(chain3.iter().all(|item| tree_vec.contains(item)));
            assert_eq!(
                mainchain_vec.len(),
                chain2.len() - len_to_cut_from_branch + new_branch_len
            );
            assert_eq!(tree_vec.len(), 45 + new_branch_len);

            check_height_order(&mainchain_vec, &tf.chainstate);
            check_height_order(&tree_vec, &tf.chainstate);

            mainchain_vec
        };
    });
}
