//TODO: need a better way than this.

use crate::utxo_impl::test_helper::{create_utxo, DIRTY, FRESH};
use crate::{flush_to_base, UtxosCache, UtxosView};
use crate::{UtxoEntry, UtxoStatus};
use common::chain::OutPoint;
use common::primitives::{Id, H256};
use crypto::random::{make_pseudo_rng, Rng};

fn random_bool() -> bool {
    let rng = make_pseudo_rng().gen_range(0..2);
    rng == 0
}

fn random_u64() -> u64 {
    make_pseudo_rng().gen_range(0..50u64)
}

fn populate_cache<'a>(
    parent: &'a UtxosCache,
    size: u64,
    existing_outpoints: &[OutPoint],
) -> (UtxosCache<'a>, Vec<OutPoint>) {
    let mut cache = UtxosCache::new(parent);

    // tracker
    let mut outps: Vec<OutPoint> = vec![];

    // let's add utxos based on `size`.
    for i in 0..size {
        let block_height = if random_bool() {
            i
        } else {
            // setting a random height based on the `size`.
            make_pseudo_rng().gen_range(0..size)
        };

        let (utxo, outpoint) = create_utxo(block_height);

        let outpoint = if random_bool() && existing_outpoints.len() > 1 {
            // setting a random existing 'spent' outpoint
            let rng = make_pseudo_rng().gen_range(0..existing_outpoints.len());
            let outpoint = &existing_outpoints[rng];

            outpoint.clone()
        } else {
            // tracking the outpoints
            outps.push(outpoint.clone());
            outpoint
        };

        // randomly set the `possible_overwrite`
        let possible_overwrite = random_bool();
        let _ = cache.add_utxo(utxo, &outpoint, possible_overwrite);

        // println!("child, insert: {:?}, overwrite: {}", outpoint,possible_overwrite );
    }

    // let's create half of the outpoints provided, to be marked as spent.
    // there's a possibility when randomly the same outpoint is used, so half seems okay.
    let spent_size = outps.len() / 2;

    for _ in 0..spent_size {
        // randomly select which outpoint should be marked as "spent"
        if random_bool() && existing_outpoints.len() > 1 {
            // just call the `spend_utxo`. Does not matter if it removes the outpoint entirely,
            // or just mark it as `spent`,
            let outp_idx = make_pseudo_rng().gen_range(0..existing_outpoints.len());
            let to_spend = &existing_outpoints[outp_idx];
            assert!(cache.spend_utxo(to_spend));

            //println!("child, spend: {:?}, removed", to_spend);
        } else {
            // just mark it as "spent"

            let outp_idx = make_pseudo_rng().gen_range(0..outps.len());
            let to_spend = &outps[outp_idx];

            let key = to_spend;

            // randomly select which flags should the spent utxo have.
            // 0 - NOT FRESH, NOT DIRTY, 1 - FRESH, 2 - DIRTY, 3 - FRESH AND DIRTY
            let flags = make_pseudo_rng().gen_range(0..4u8);

            let new_entry = match flags {
                FRESH => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: false,
                    is_fresh: true,
                },
                DIRTY => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: true,
                    is_fresh: false,
                },
                flag if flag == (FRESH + DIRTY) => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: true,
                    is_fresh: true,
                },
                _ => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: false,
                    is_fresh: false,
                },
            };
            cache.utxos.insert(key.clone(), new_entry);

            //println!("child, spend: {:?}, flags: {}", to_spend,flags );
        };
    }

    (cache, outps)
}

// #[test]
fn stack_flush_test() {
    let mut outps: Vec<OutPoint> = vec![];

    let block_hash = Id::new(&H256::random());
    let mut parent = UtxosCache::default();
    parent.set_best_block(block_hash);

    let parent_clone = parent.clone();
    let (cache1, mut cache1_outps) = populate_cache(&parent_clone, random_u64(), &outps);
    outps.append(&mut cache1_outps);

    let cache1_clone = cache1.clone();
    let (cache2, mut cache2_outps) = populate_cache(&cache1_clone, random_u64(), &outps);
    outps.append(&mut cache2_outps);

    let cache2_clone = cache2.clone();
    let (mut cache3, mut cache3_outps) = populate_cache(&cache2_clone, random_u64(), &outps);
    outps.append(&mut cache3_outps);

    let new_block_hash = Id::new(&H256::random());
    cache3.set_best_block(new_block_hash);
    let cache3_clone = cache3.clone();
    assert!(flush_to_base(cache3_clone, &mut parent).is_ok());

    for (key, utxo_entry) in &parent.utxos {
        let outpoint = key;
        let utxo = cache3.get_utxo(outpoint);

        assert_eq!(utxo_entry.utxo(), utxo);
    }
}
