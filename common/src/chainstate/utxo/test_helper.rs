use crate::chain::{Destination, OutPoint, OutPointSourceId, Transaction, TxOutput};
use crate::chainstate::utxo::{OutPointKey, Utxo, UtxoEntry, UtxosCache};
use crate::primitives::{Amount, BlockHeight, Id, H256};
use rand::Rng;

pub const FRESH: u8 = 1;
pub const DIRTY: u8 = 2;

#[derive(Clone, Eq, PartialEq)]
pub enum Presence {
    Absent,
    Present,
    Spent,
}

use crate::chain::block::Block;
use Presence::{Absent, Present, Spent};
use crate::utxo::UtxoStatus;

pub fn create_utxo(block_height: u64) -> (Utxo, OutPoint) {
    let rng = rand::thread_rng().gen_range(0..u128::MAX);
    let output = TxOutput::new(Amount::new(rng), Destination::PublicKey);
    let is_block_reward = rng % 3 == 0;
    let utxo = Utxo::new(output, is_block_reward, BlockHeight::new(block_height));

    let id = {
        if !is_block_reward {
            let utxo_id: Id<Transaction> = Id::new(&H256::random());
            OutPointSourceId::Transaction(utxo_id)
        } else {
            let utxo_id: Id<Block> = Id::new(&H256::random());
            OutPointSourceId::BlockReward(utxo_id)
        }
    };
    let outpoint = OutPoint::new(id, 0);

    (utxo, outpoint)
}

/// inserts a random utxo in the cache.
/// returns the utxo and the outpoint.
/// # Arguments
/// `cache` - a mutable reference of the UtxosCache
/// `cache_presence` - sets the initial state of the cache.
/// `cache_flags` - sets the entry of the utxo (fresh/not, dirty/not)
/// `outpoint` - optional key to be used, rather than a randomly generated one.
pub fn insert_single_entry(
    cache: &mut UtxosCache,
    cache_presence: &Presence,
    cache_flags: Option<u8>,
    outpoint: Option<OutPoint>,
) -> (Utxo, OutPoint) {
    let rng_height = rand::thread_rng().gen_range(0..(u64::MAX - 1));
    let (utxo, outpoint_x) = create_utxo(rng_height);
    let outpoint = outpoint.unwrap_or(outpoint_x);
    let key = OutPointKey::from(&outpoint);

    match cache_presence {
        Absent => {
            // there shouldn't be an existing entry. Don't bother with the cache flags.
        }
        other => {
            let flags = cache_flags.expect("please provide flags.");
            let is_dirty = (flags & DIRTY) == DIRTY;
            let is_fresh = (flags & FRESH) == FRESH;

            let entry = match other {
                Present => UtxoEntry::new(utxo.clone(), is_fresh, is_dirty),
                Spent => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty,
                    is_fresh
                },
                _ => {
                    panic!("something wrong in the code.")
                }
            };

            // let's insert an entry.
            cache.utxos.insert(key, entry);
        }
    }

    (utxo, outpoint)
}

/// checks the dirty, fresh, and spent flags.
pub fn check_flags(result_entry: Option<&UtxoEntry>, expected_flags: Option<u8>, is_spent: bool) {
    if let Some(flags) = expected_flags {
        let result_entry = result_entry.expect("this should have an entry inside");

        assert_eq!(result_entry.is_dirty(), (flags & DIRTY) == DIRTY);
        assert_eq!(result_entry.is_fresh(), (flags & FRESH) == FRESH);
        assert_eq!(result_entry.is_spent(), is_spent);
    } else {
        assert!(result_entry.is_none());
    }
}
