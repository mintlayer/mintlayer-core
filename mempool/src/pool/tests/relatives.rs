// Copyright (c) 2026 RBB S.r.l
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

use std::{
    collections::BTreeSet,
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
};

use itertools::Itertools as _;
use rstest::rstest;

use ::utils::shuffled::Shuffled as _;
use chainstate_test_framework::{
    TestFramework as ChainstateTestFramework,
    helpers::{make_simple_coin_tx, make_simple_coin_tx_with_witness_sizes},
};
use common::{
    chain::{self, ChainConfig, Genesis, OutPointSourceId, SignedTransaction},
    primitives::{Amount, Id, Idable},
};
use logging::log;
use randomness::{CryptoRng, RngExt as _};
use serialization::Encode as _;
use test_utils::{
    assert_matches,
    random::{Seed, make_seedable_rng},
};

use crate::{
    FeeRate,
    config::{MaxClusterSizeBytes, MaxClusterTxCount, MempoolConfig},
    error::{Error, MempoolPolicyError},
    pool::{
        Mempool, TxStatus,
        memory_usage_estimator::StoreMemoryUsageEstimator,
        tx_pool::{self, tests::utils::start_chainstate},
    },
};

// A general test that creates a tx tree and adds the txs to the mempool, checking clusters,
// ancestors and descendants of each tx.
// Several subtests exist, which use different cluster tx count limits and avoid/force orphans
// creation.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_relatives_and_cluster_tx_count_limit(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut ctf = ChainstateTestFramework::builder(&mut rng).build();
    let tf = TestFramework::new(&mut rng, ctf.genesis().get_id());

    ctf.make_block_builder()
        .add_transaction(tf.funding_tx().clone())
        .build_and_process(&mut rng)
        .unwrap();

    let id = |tx: &SignedTransaction| tx.transaction().get_id();

    let chain_config = Arc::clone(ctf.chain_config());
    let chainstate_handle = start_chainstate(ctf.chainstate());

    let create_mempool = |max_cluster_tx_count: usize| {
        self::create_mempool(
            Arc::clone(&chain_config),
            chainstate_handle.clone(),
            max_cluster_tx_count.into(),
            Default::default(),
        )
    };

    let a0 = tf.mk_base_tx();
    let a1 = tf.mk_base_tx();
    let a2 = tf.mk_base_tx();
    let a3 = tf.mk_base_tx();
    let a4 = tf.mk_base_tx();

    // b0 depends on a0, a1
    let b0 = tf.mk_tx(&[(id(&a0).into(), 0), (id(&a1).into(), 0)], 1);
    // b1 depends on a2, a3, a4
    let b1 = tf.mk_tx(
        &[(id(&a2).into(), 0), (id(&a3).into(), 0), (id(&a4).into(), 0)],
        1,
    );
    // b2 depends on a2, a3
    let b2 = tf.mk_tx(&[(id(&a2).into(), 1), (id(&a3).into(), 1)], 1);
    // b3 depends on a2
    let b3 = tf.mk_tx(&[(id(&a2).into(), 2)], 1);
    // b4, b5, b6 all depend on a4
    let b4 = tf.mk_tx(&[(id(&a4).into(), 1)], 1);
    let b5 = tf.mk_tx(&[(id(&a4).into(), 2)], 1);
    let b6 = tf.mk_tx(&[(id(&a4).into(), 3)], 1);
    // c0 depends on b0, b1
    let c0 = tf.mk_tx(&[(id(&b0).into(), 0), (id(&b1).into(), 0)], 2);
    // d0, d1 depend on c0
    let d0 = tf.mk_tx(&[(id(&c0).into(), 0)], 3);
    let d1 = tf.mk_tx(&[(id(&c0).into(), 1)], 3);

    let all_a = [&a0, &a1, &a2, &a3, &a4];
    let all_b = [&b0, &b1, &b2, &b3, &b4, &b5, &b6];

    for (idx, tx) in all_a.iter().enumerate() {
        log::debug!("a{idx}: {:x}", id(tx));
    }
    for (idx, tx) in all_b.iter().enumerate() {
        log::debug!("b{idx}: {:x}", id(tx));
    }
    log::debug!("c0: {:x}", id(&c0));
    log::debug!("d0: {:x}", id(&d0));
    log::debug!("d1: {:x}", id(&d1));

    // The tx tree looks like this:
    //             a0 ->----\
    // b3 --\      a1 ->---- b0 -\
    //       \                    \     /--- d0
    // b2-------<- a2 ->---\       -- c0 --- d1
    //   \------<- a3 ->---- b1 --/
    //                     /
    //                    /- b4
    //             a4 ->---- b5
    //                    \- b6

    // Simple subtest with a small cluster size limit.
    {
        let mut mempool = create_mempool(3);

        for tx in all_a.iter().collect_vec().shuffled(&mut rng) {
            add_tx_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &all_a);
        assert_orphans(&mempool, &[]);

        // Each 'a' is a separate cluster at this moment.
        for tx in &all_a {
            assert_cluster(&mempool, &[tx]);
        }

        add_tx_ok(&mut mempool, &b0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2]);
        assert_cluster(&mempool, &[&a3]);
        assert_cluster(&mempool, &[&a4]);

        // This would create a cluster of 4
        add_tx_expect_cluster_cnt_failure(&mut mempool, &b1);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2]);
        assert_cluster(&mempool, &[&a3]);
        assert_cluster(&mempool, &[&a4]);

        add_tx_ok(&mut mempool, &b2);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b2]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &b2]);
        assert_cluster(&mempool, &[&a4]);

        // This would create a cluster of 4
        add_tx_expect_cluster_cnt_failure(&mut mempool, &b3);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b2]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &b2]);
        assert_cluster(&mempool, &[&a4]);

        add_tx_ok(&mut mempool, &b4);
        add_tx_ok(&mut mempool, &b5);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b2, &b4, &b5]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &b2]);
        assert_cluster(&mempool, &[&a4, &b4, &b5]);

        add_tx_expect_cluster_cnt_failure(&mut mempool, &b6);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b2, &b4, &b5]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &b2]);
        assert_cluster(&mempool, &[&a4, &b4, &b5]);

        // c0 will be an orphan, since b1 was rejected and di depend on c0
        for tx in [&c0, &d0, &d1].shuffled(&mut rng) {
            add_orphan_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b2, &b4, &b5]);
        assert_orphans(&mempool, &[&c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &b2]);
        assert_cluster(&mempool, &[&a4, &b4, &b5]);

        // Now also check ancestors and descendants of each tx, grouping the checks by cluster.
        // Cluster 1.
        assert_ancestors(&mempool, &a0, &[]);
        assert_descendants(&mempool, &a0, &[&b0]);
        assert_ancestors(&mempool, &a1, &[]);
        assert_descendants(&mempool, &a1, &[&b0]);
        assert_ancestors(&mempool, &b0, &[&a0, &a1]);
        assert_descendants(&mempool, &b0, &[]);
        // Cluster 2.
        assert_ancestors(&mempool, &a2, &[]);
        assert_descendants(&mempool, &a2, &[&b2]);
        assert_ancestors(&mempool, &a3, &[]);
        assert_descendants(&mempool, &a3, &[&b2]);
        assert_ancestors(&mempool, &b2, &[&a2, &a3]);
        assert_descendants(&mempool, &b2, &[]);
        // Cluster 3.
        assert_ancestors(&mempool, &a4, &[]);
        assert_descendants(&mempool, &a4, &[&b4, &b5]);
        assert_ancestors(&mempool, &b4, &[&a4]);
        assert_descendants(&mempool, &b4, &[]);
        assert_ancestors(&mempool, &b5, &[&a4]);
        assert_descendants(&mempool, &b5, &[]);
    }

    // Same as above, but we add a's at the end, so all other txs are initially orphans
    {
        let mut mempool = create_mempool(3);

        // Add all txs except a's and b6, they will all become orphans (b6 is omitted because
        // it'd make clusters non-predictable - they'd depend on which of b4, b5, b6 is picked
        // from the orphan pool first).
        for tx in [&b0, &b1, &b2, &b3, &b4, &b5, &c0, &d0, &d1].shuffled(&mut rng) {
            add_orphan_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &[]);
        assert_orphans(&mempool, &[&b0, &b1, &b2, &b3, &b4, &b5, &c0, &d0, &d1]);

        // Now add a's one by one. Note that due to tx dependencies, b's will be entering
        // the mempool in a different order, so different clusters will form and different
        // txs will be rejected compared to the test above.

        add_tx_ok(&mut mempool, &a0);
        assert_txs(&mempool, &[&a0]);
        assert_orphans(&mempool, &[&b0, &b1, &b2, &b3, &b4, &b5, &c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0]);

        // After this, b0 is no longer an orphan
        add_tx_ok(&mut mempool, &a1);
        assert_txs(&mempool, &[&a0, &a1, &b0]);
        assert_orphans(&mempool, &[&b1, &b2, &b3, &b4, &b5, &c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);

        // After this, b3 is no longer an orphan
        add_tx_ok(&mut mempool, &a2);
        assert_txs(&mempool, &[&a0, &a1, &a2, &b0, &b3]);
        assert_orphans(&mempool, &[&b1, &b2, &b4, &b5, &c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &b3]);

        // This will attempt to add b2 to the pool, but it would result in a cluster of size 4,
        // so b2 will be rejected
        add_tx_ok(&mut mempool, &a3);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b3]);
        assert_orphans(&mempool, &[&b1, &b4, &b5, &c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &b3]);
        assert_cluster(&mempool, &[&a3]);

        // After this, b1, b4 and b5 are no longer orphans. But adding b1 would result in a cluster
        // of size 4 (even if it's selected first), so it will be dropped.
        // (b4 and b5 will be added successfully because we didn't add b6 initially).
        add_tx_ok(&mut mempool, &a4);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b3, &b4, &b5]);
        assert_orphans(&mempool, &[&c0, &d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &b3]);
        assert_cluster(&mempool, &[&a3]);
        assert_cluster(&mempool, &[&a4, &b4, &b5]);

        // Check ancestors and descendants of each tx.
        // Cluster 1.
        assert_ancestors(&mempool, &a0, &[]);
        assert_descendants(&mempool, &a0, &[&b0]);
        assert_ancestors(&mempool, &a1, &[]);
        assert_descendants(&mempool, &a1, &[&b0]);
        assert_ancestors(&mempool, &b0, &[&a0, &a1]);
        assert_descendants(&mempool, &b0, &[]);
        // Cluster 2.
        assert_ancestors(&mempool, &a2, &[]);
        assert_descendants(&mempool, &a2, &[&b3]);
        assert_ancestors(&mempool, &b3, &[&a2]);
        assert_descendants(&mempool, &b3, &[]);
        // Cluster 3.
        assert_ancestors(&mempool, &a3, &[]);
        assert_descendants(&mempool, &a3, &[]);
        // Cluster 4.
        assert_ancestors(&mempool, &a4, &[]);
        assert_descendants(&mempool, &a4, &[&b4, &b5]);
        assert_ancestors(&mempool, &b4, &[&a4]);
        assert_descendants(&mempool, &b4, &[]);
        assert_ancestors(&mempool, &b5, &[&a4]);
        assert_descendants(&mempool, &b5, &[]);
    }

    // A non-orphan subtest with a bigger limit
    {
        let mut mempool = create_mempool(5);

        for tx in all_a.iter().collect_vec().shuffled(&mut rng) {
            add_tx_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &all_a);
        assert_orphans(&mempool, &[]);

        // Each 'a' is a separate cluster at this moment.
        for tx in &all_a {
            assert_cluster(&mempool, &[tx]);
        }

        add_tx_ok(&mut mempool, &b0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2]);
        assert_cluster(&mempool, &[&a3]);
        assert_cluster(&mempool, &[&a4]);

        add_tx_ok(&mut mempool, &b1);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &a4, &b1]);

        add_tx_ok(&mut mempool, &b2);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1, &b2]);
        assert_orphans(&mempool, &[]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &a4, &b1, &b2]);

        // Any of these would contribute to the larger cluster, which is already of size 5,
        // so they will be rejected.
        for tx in [&b3, &b4, &b5, &b6, &c0].shuffled(&mut rng) {
            add_tx_expect_cluster_cnt_failure(&mut mempool, tx);
            assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1, &b2]);
            assert_orphans(&mempool, &[]);
            assert_cluster(&mempool, &[&a0, &a1, &b0]);
            assert_cluster(&mempool, &[&a2, &a3, &a4, &b1, &b2]);
        }

        // d's will become orphans
        for tx in [&d0, &d1].shuffled(&mut rng) {
            add_orphan_ok(&mut mempool, tx);
        }

        assert_orphans(&mempool, &[&d0, &d1]);
        assert_cluster(&mempool, &[&a0, &a1, &b0]);
        assert_cluster(&mempool, &[&a2, &a3, &a4, &b1, &b2]);

        // Check ancestors and descendants of each tx.
        // Cluster 1.
        assert_ancestors(&mempool, &a0, &[]);
        assert_descendants(&mempool, &a0, &[&b0]);
        assert_ancestors(&mempool, &a1, &[]);
        assert_descendants(&mempool, &a1, &[&b0]);
        assert_ancestors(&mempool, &b0, &[&a0, &a1]);
        assert_descendants(&mempool, &b0, &[]);
        // Cluster 2.
        assert_ancestors(&mempool, &a2, &[]);
        assert_descendants(&mempool, &a2, &[&b1, &b2]);
        assert_ancestors(&mempool, &a3, &[]);
        assert_descendants(&mempool, &a3, &[&b1, &b2]);
        assert_ancestors(&mempool, &a4, &[]);
        assert_descendants(&mempool, &a4, &[&b1]);
        assert_ancestors(&mempool, &b1, &[&a2, &a3, &a4]);
        assert_descendants(&mempool, &b1, &[]);
        assert_ancestors(&mempool, &b2, &[&a2, &a3]);
        assert_descendants(&mempool, &b2, &[]);
    }

    // A non-orphan subtest with the default limit. All txs will be added and form a single cluster.
    {
        let mut mempool = create_mempool(*MaxClusterTxCount::default());

        let all_txs = {
            let mut all_txs = all_a.iter().copied().collect_vec();
            all_txs.extend(&all_b);
            all_txs.extend([&c0, &d0, &d1]);
            all_txs
        };
        let all_txs_shuffled = all_txs.clone().shuffled(&mut rng);

        for (idx, tx) in all_txs_shuffled.iter().enumerate() {
            log::debug!("shuffled tx #{idx}: {:x}", id(tx));
        }

        for tx in &all_txs_shuffled {
            let status = mempool.add_transaction_test((*tx).clone()).unwrap();
            assert!(status == TxStatus::InMempool || status == TxStatus::InOrphanPool);
        }

        assert_orphans(&mempool, &[]);
        assert_txs(&mempool, &all_txs);
        assert_cluster(&mempool, &all_txs);

        // Check ancestors and descendants of each tx.
        // A's
        assert_ancestors(&mempool, &a0, &[]);
        assert_descendants(&mempool, &a0, &[&b0, &c0, &d0, &d1]);
        assert_ancestors(&mempool, &a1, &[]);
        assert_descendants(&mempool, &a1, &[&b0, &c0, &d0, &d1]);
        assert_ancestors(&mempool, &a2, &[]);
        assert_descendants(&mempool, &a2, &[&b1, &b2, &b3, &c0, &d0, &d1]);
        assert_ancestors(&mempool, &a3, &[]);
        assert_descendants(&mempool, &a3, &[&b1, &b2, &c0, &d0, &d1]);
        assert_ancestors(&mempool, &a4, &[]);
        assert_descendants(&mempool, &a4, &[&b1, &b4, &b5, &b6, &c0, &d0, &d1]);
        // B's
        assert_ancestors(&mempool, &b0, &[&a0, &a1]);
        assert_descendants(&mempool, &b0, &[&c0, &d0, &d1]);
        assert_ancestors(&mempool, &b1, &[&a2, &a3, &a4]);
        assert_descendants(&mempool, &b1, &[&c0, &d0, &d1]);
        assert_ancestors(&mempool, &b2, &[&a2, &a3]);
        assert_descendants(&mempool, &b2, &[]);
        assert_ancestors(&mempool, &b3, &[&a2]);
        assert_descendants(&mempool, &b3, &[]);
        assert_ancestors(&mempool, &b4, &[&a4]);
        assert_descendants(&mempool, &b4, &[]);
        assert_ancestors(&mempool, &b5, &[&a4]);
        assert_descendants(&mempool, &b5, &[]);
        assert_ancestors(&mempool, &b6, &[&a4]);
        assert_descendants(&mempool, &b6, &[]);
        // C's
        assert_ancestors(&mempool, &c0, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1]);
        assert_descendants(&mempool, &c0, &[&d0, &d1]);
        // D's
        assert_ancestors(&mempool, &d0, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1, &c0]);
        assert_descendants(&mempool, &d0, &[]);
        assert_ancestors(&mempool, &d1, &[&a0, &a1, &a2, &a3, &a4, &b0, &b1, &c0]);
        assert_descendants(&mempool, &d1, &[]);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cluster_byte_size(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let chain_config = chain::config::create_unit_test_config_builder()
        // In this test we'll vary witness data length to make txs of the desired size.
        .data_in_no_signature_witness_max_size(10_000)
        .build();
    let mut ctf = ChainstateTestFramework::builder(&mut rng)
        .with_chain_config(chain_config)
        .build();
    let tf = TestFramework::new(&mut rng, ctf.genesis().get_id());

    ctf.make_block_builder()
        .add_transaction(tf.funding_tx().clone())
        .build_and_process(&mut rng)
        .unwrap();

    let id = |tx: &SignedTransaction| tx.transaction().get_id();

    let chain_config = Arc::clone(ctf.chain_config());
    let chainstate_handle = start_chainstate(ctf.chainstate());

    let create_mempool = |max_cluster_size_bytes: usize| {
        self::create_mempool(
            Arc::clone(&chain_config),
            chainstate_handle.clone(),
            Default::default(),
            max_cluster_size_bytes.into(),
        )
    };

    // a's and d0  will all have 1 input (and all txs have the same number of outputs),
    // so they will have the same size, not counting the witness.
    let ad_tx = tf.mk_base_tx_with_sig_size(1000);
    let ad_tx_base_size = ad_tx.encoded_size() - 1000;

    // same for b0, b1 and c0, which will all have 2 inputs.
    let bc_tx_base_size = tf
        .mk_tx_with_sig_size(
            &[(id(&ad_tx).into(), 0, 1000), (id(&ad_tx).into(), 0, 0)],
            1,
        )
        .encoded_size()
        - 1000;

    let a_size = 1000;
    let b0_size = 1000;
    let b1_size = 2000;
    let c0_size = 1000;
    let d0_size = 1000;

    let a0 = tf.mk_base_tx_with_sig_size(a_size - ad_tx_base_size);
    let a1 = tf.mk_base_tx_with_sig_size(a_size - ad_tx_base_size);
    let a2 = tf.mk_base_tx_with_sig_size(a_size - ad_tx_base_size);
    let a3 = tf.mk_base_tx_with_sig_size(a_size - ad_tx_base_size);

    // b0 depends on a0, a1
    let b0 = tf.mk_tx_with_sig_size(
        &[(id(&a0).into(), 0, b0_size - bc_tx_base_size), (id(&a1).into(), 0, 0)],
        1,
    );
    // b1 depends on a2, a3
    let b1 = tf.mk_tx_with_sig_size(
        &[(id(&a2).into(), 0, b1_size - bc_tx_base_size), (id(&a3).into(), 0, 0)],
        1,
    );
    // c0 depends on b0, b1
    let c0 = tf.mk_tx_with_sig_size(
        &[(id(&b0).into(), 0, c0_size - bc_tx_base_size), (id(&b1).into(), 0, 0)],
        2,
    );
    // d0 depends on c0
    let d0 = tf.mk_tx_with_sig_size(&[(id(&c0).into(), 0, d0_size - ad_tx_base_size)], 3);

    let all_a = [&a0, &a1, &a2, &a3];

    for (idx, tx) in all_a.iter().enumerate() {
        log::debug!("a{idx}: id={:x}, size={}", id(tx), tx.encoded_size());
    }
    log::debug!("b0: id={:x}, size={}", id(&b0), b0.encoded_size());
    log::debug!("b1: id={:x}, size={}", id(&b1), b1.encoded_size());
    log::debug!("c0: id={:x}, size={}", id(&c0), c0.encoded_size());
    log::debug!("d0: id={:x}, size={}", id(&d0), d0.encoded_size());

    // The tx tree looks like this:
    // a0 ->----\
    // a1 ->---- b0 -\
    //                \
    // a2 ->---\       -- c0 --- d0
    // a3 ->---- b1 --/

    let b0_cluster_size = a_size * 2 + b0_size;
    let b1_cluster_size = a_size * 2 + b1_size;
    let c0_cluster_size = b0_cluster_size + b1_cluster_size + c0_size;
    let d0_cluster_size = c0_cluster_size + d0_size;

    // Sanity check
    assert!(b1_cluster_size > b0_cluster_size);

    // A simple subtest with a small byte size limit
    {
        let limit = b0_cluster_size + rng.random_range(0..(b1_cluster_size - b0_cluster_size));
        let mut mempool = create_mempool(limit);

        for tx in all_a.iter().collect_vec().shuffled(&mut rng) {
            add_tx_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &all_a);
        assert_orphans(&mempool, &[]);

        // Each 'a' is a separate cluster at this moment.
        for tx in &all_a {
            assert_cluster(&mempool, &[tx]);
        }

        add_tx_ok(&mut mempool, &b0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);

        // This would result in cluster with size b1_cluster_size
        add_tx_expect_cluster_byte_size_failure(&mut mempool, &b1);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);

        // c0 will be an orphan, since b1 was rejected and d0 depends on c0
        add_orphan_ok(&mut mempool, &c0);
        add_orphan_ok(&mut mempool, &d0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[&c0, &d0]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);
    }

    // Same as above, but we add a's at the end, so all other txs are initially orphans
    {
        let limit = b0_cluster_size + rng.random_range(0..(b1_cluster_size - b0_cluster_size));
        let mut mempool = create_mempool(limit);

        for tx in [&b0, &b1, &c0, &d0].shuffled(&mut rng) {
            add_orphan_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &[]);
        assert_orphans(&mempool, &[&b0, &b1, &c0, &d0]);

        // b0 is still an orphan
        add_tx_ok(&mut mempool, &a0);
        assert_txs(&mempool, &[&a0]);
        assert_orphans(&mempool, &[&b0, &b1, &c0, &d0]);
        assert_cluster_with_size(&mempool, &[&a0], a_size);

        // b0 is no longer an orphan
        add_tx_ok(&mut mempool, &a1);
        assert_txs(&mempool, &[&a0, &a1, &b0]);
        assert_orphans(&mempool, &[&b1, &c0, &d0]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);

        // b1 is still an orphan
        add_tx_ok(&mut mempool, &a2);
        assert_txs(&mempool, &[&a0, &a1, &a2, &b0]);
        assert_orphans(&mempool, &[&b1, &c0, &d0]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);

        // b1 is no longer an orphan, but adding it to the mempool would create a cluster of
        // size b1_cluster_size, so it'll be discarded.
        add_tx_ok(&mut mempool, &a3);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[&c0, &d0]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);
    }

    // A non-orphan subtest with a bigger byte size limit, enough to include b1, but not c0.
    {
        let limit = b1_cluster_size + rng.random_range(0..(c0_cluster_size - b1_cluster_size));
        let mut mempool = create_mempool(limit);

        for tx in all_a.iter().collect_vec().shuffled(&mut rng) {
            add_tx_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &all_a);
        assert_orphans(&mempool, &[]);

        // Each 'a' is a separate cluster at this moment.
        for tx in &all_a {
            assert_cluster(&mempool, &[tx]);
        }

        add_tx_ok(&mut mempool, &b0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);

        add_tx_ok(&mut mempool, &b1);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2, &a3, &b1], b1_cluster_size);

        // This would result in cluster with size c0_cluster_size
        add_tx_expect_cluster_byte_size_failure(&mut mempool, &c0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2, &a3, &b1], b1_cluster_size);

        // d0 will be an orphan, since c0 was rejected
        add_orphan_ok(&mut mempool, &d0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1]);
        assert_orphans(&mempool, &[&d0]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2, &a3, &b1], b1_cluster_size);
    }

    // A non-orphan subtest with a bigger byte size limit, enough to include c0, but not d0.
    {
        let limit = c0_cluster_size + rng.random_range(0..(d0_cluster_size - c0_cluster_size));
        let mut mempool = create_mempool(limit);

        for tx in all_a.iter().collect_vec().shuffled(&mut rng) {
            add_tx_ok(&mut mempool, tx);
        }

        assert_txs(&mempool, &all_a);
        assert_orphans(&mempool, &[]);

        // Each 'a' is a separate cluster at this moment.
        for tx in &all_a {
            assert_cluster(&mempool, &[tx]);
        }

        add_tx_ok(&mut mempool, &b0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2], a_size);
        assert_cluster_with_size(&mempool, &[&a3], a_size);

        add_tx_ok(&mut mempool, &b1);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(&mempool, &[&a0, &a1, &b0], b0_cluster_size);
        assert_cluster_with_size(&mempool, &[&a2, &a3, &b1], b1_cluster_size);

        add_tx_ok(&mut mempool, &c0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1, &c0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(
            &mempool,
            &[&a0, &a1, &a2, &a3, &b0, &b1, &c0],
            c0_cluster_size,
        );

        // This would result in cluster with size d0_cluster_size
        add_tx_expect_cluster_byte_size_failure(&mut mempool, &d0);
        assert_txs(&mempool, &[&a0, &a1, &a2, &a3, &b0, &b1, &c0]);
        assert_orphans(&mempool, &[]);
        assert_cluster_with_size(
            &mempool,
            &[&a0, &a1, &a2, &a3, &b0, &b1, &c0],
            c0_cluster_size,
        );
    }
}

struct TestFramework {
    rng: Mutex<Box<dyn CryptoRng + Send>>,
    fund_amount: u128,
    funding_tx: SignedTransaction,
    next_fund_tx_output_idx: Mutex<u32>,
}

impl TestFramework {
    pub fn new(orig_rng: &mut impl CryptoRng, genesis_id: Id<Genesis>) -> Self {
        let fund_amount = 1_000_000_000;
        let funding_tx = make_simple_coin_tx(
            orig_rng,
            [(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
            [fund_amount; 100],
        );

        Self {
            rng: Mutex::new(Box::new(make_seedable_rng(orig_rng.random()))),
            fund_amount: 1_000_000_000,
            funding_tx,
            next_fund_tx_output_idx: Mutex::new(0),
        }
    }

    fn lock_rng(&self) -> MutexGuard<'_, Box<dyn CryptoRng + Send>> {
        self.rng.lock().unwrap()
    }

    pub fn funding_tx(&self) -> &SignedTransaction {
        &self.funding_tx
    }

    // For simplicity, all txs in these tests will have 10 outputs.
    // The "level" here must be the max "distance" from this tx and the funding tx, and it determines
    // the size of the outputs.
    fn mk_tx_outputs(&self, level: u32) -> impl IntoIterator<Item = u128> {
        [self.fund_amount / 10u128.pow(level + 1); 10]
    }

    pub fn mk_tx(&self, ins: &[(OutPointSourceId, u32)], level: u32) -> SignedTransaction {
        make_simple_coin_tx(
            self.lock_rng().deref_mut(),
            ins.iter().cloned(),
            self.mk_tx_outputs(level),
        )
    }

    pub fn mk_tx_with_sig_size(
        &self,
        ins: &[(OutPointSourceId, u32, usize)],
        level: u32,
    ) -> SignedTransaction {
        make_simple_coin_tx_with_witness_sizes(
            self.lock_rng().deref_mut(),
            ins.iter().cloned(),
            self.mk_tx_outputs(level),
        )
    }

    pub fn mk_base_tx(&self) -> SignedTransaction {
        self.mk_tx(
            &[(
                self.funding_tx.transaction().get_id().into(),
                self.next_fund_tx_output_idx(),
            )],
            0,
        )
    }

    pub fn mk_base_tx_with_sig_size(&self, sig_size: usize) -> SignedTransaction {
        self.mk_tx_with_sig_size(
            &[(
                self.funding_tx.transaction().get_id().into(),
                self.next_fund_tx_output_idx(),
                sig_size,
            )],
            0,
        )
    }

    fn next_fund_tx_output_idx(&self) -> u32 {
        let mut next_idx = self.next_fund_tx_output_idx.lock().unwrap();
        let old_idx = *next_idx;

        *next_idx += 1;

        old_idx
    }
}

type MempoolType = Mempool<StoreMemoryUsageEstimator>;

fn create_mempool(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    max_cluster_tx_count: MaxClusterTxCount,
    max_cluster_size_bytes: MaxClusterSizeBytes,
) -> MempoolType {
    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
        max_cluster_tx_count,
        max_cluster_size_bytes,
    };
    Mempool::new(
        chain_config,
        mempool_config,
        chainstate_handle,
        Default::default(),
        StoreMemoryUsageEstimator,
    )
    .unwrap()
}

fn add_tx_ok(mempool: &mut MempoolType, tx: &SignedTransaction) {
    let status = mempool.add_transaction_test(tx.clone()).unwrap();
    assert_eq!(status, TxStatus::InMempool);
}

fn add_orphan_ok(mempool: &mut MempoolType, tx: &SignedTransaction) {
    let status = mempool.add_transaction_test(tx.clone()).unwrap();
    assert_eq!(status, TxStatus::InOrphanPool);
}

fn add_tx_expect_cluster_cnt_failure(mempool: &mut MempoolType, tx: &SignedTransaction) {
    let err = mempool.add_transaction_test(tx.clone()).unwrap_err();
    assert_matches!(
        err,
        Error::Policy(MempoolPolicyError::ClusterMaxTxCountLimitViolated { .. })
    );
}

fn add_tx_expect_cluster_byte_size_failure(mempool: &mut MempoolType, tx: &SignedTransaction) {
    let err = mempool.add_transaction_test(tx.clone()).unwrap_err();
    assert_matches!(
        err,
        Error::Policy(MempoolPolicyError::ClusterTotalTxSizeLimitViolated { .. })
    );
}

fn assert_txs(mempool: &MempoolType, txs: &[&SignedTransaction]) {
    let actual_tx_ids = mempool
        .get_all_by_descendant_score()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect::<BTreeSet<_>>();
    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect::<BTreeSet<_>>();
    assert_eq!(actual_tx_ids, expected_tx_ids);
}

fn assert_orphans(mempool: &MempoolType, txs: &[&SignedTransaction]) {
    let actual_tx_ids =
        mempool.get_all_orphan_transaction_ids().into_iter().collect::<BTreeSet<_>>();
    let expected_tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect::<BTreeSet<_>>();
    assert_eq!(actual_tx_ids, expected_tx_ids);
}

fn assert_cluster(mempool: &MempoolType, txs: &[&SignedTransaction]) {
    let tx_ids = txs.iter().map(|tx| tx.transaction().get_id()).collect::<BTreeSet<_>>();
    // txs must be unique
    assert_eq!(tx_ids.len(), txs.len());
    tx_pool::tests::utils::assert_cluster(mempool.tx_store(), &tx_ids);
}

fn assert_cluster_with_size(
    mempool: &MempoolType,
    txs: &[&SignedTransaction],
    expected_total_size: usize,
) {
    assert_cluster(mempool, txs);

    let mut total_size = 0;
    for tx in txs {
        let tx_id = tx.transaction().get_id();
        let entry = mempool.tx_store().get_entry(&tx_id).unwrap();
        let recorded_tx_size = entry.size().get();
        let actual_tx_size = tx.encoded_size();
        assert_eq!(recorded_tx_size, actual_tx_size, "tx_id = {tx_id:x}");
        total_size += actual_tx_size;
    }

    assert_eq!(total_size, expected_total_size);
}

fn assert_ancestors(
    mempool: &MempoolType,
    tx: &SignedTransaction,
    ancestor_txs: &[&SignedTransaction],
) {
    let ancestor_tx_ids =
        ancestor_txs.iter().map(|tx| tx.transaction().get_id()).collect::<BTreeSet<_>>();
    tx_pool::tests::utils::assert_ancestors(
        mempool.tx_store(),
        &tx.transaction().get_id(),
        &ancestor_tx_ids,
    );
}

fn assert_descendants(
    mempool: &MempoolType,
    tx: &SignedTransaction,
    descendant_txs: &[&SignedTransaction],
) {
    let descendant_tx_ids = descendant_txs
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect::<BTreeSet<_>>();
    tx_pool::tests::utils::assert_descendants(
        mempool.tx_store(),
        &tx.transaction().get_id(),
        &descendant_tx_ids,
    );
}
