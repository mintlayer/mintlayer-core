// Copyright (c) 2022 RBB S.r.l
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

use common::primitives::{BlockHeight, Id, Idable, H256};

use crate::utxo_impl::test_helper::Presence::{Absent, Present, Spent};
use crate::Error::{self, FreshUtxoAlreadyExists, OverwritingUtxo};
use crate::{
    flush_to_base, ConsumedUtxoCache, FlushableUtxoView, Utxo, UtxoEntry, UtxosCache, UtxosView,
};

use crate::test_helper::create_tx_outputs;
use crate::utxo_impl::test_helper::{
    check_flags, create_utxo, create_utxo_for_mempool, insert_single_entry, Presence, DIRTY, FRESH,
};
use crate::utxo_impl::{UtxoSource, UtxoStatus};
use common::chain::{OutPoint, OutPointSourceId, Transaction, TxInput};
use crypto::random::{seq, Rng};
use itertools::Itertools;
use rstest::rstest;
use std::collections::BTreeMap;
use test_utils::random::{make_seedable_rng, Seed};

/// Checks `add_utxo` method behaviour.
/// # Arguments
/// `cache_presence` - initial state of the cache
/// `cache_flags` - The flags of the existing utxo entry for testing
/// `possible_overwrite` - to set the `possible_overwrite` of the `add_utxo` method
/// `result_flags` - the result ( dirty/not, fresh/not ) after calling the `add_utxo` method.
/// `op_result` - the result of calling `add_utxo` method, whether it succeeded or not.
fn check_add_utxo(
    rng: &mut impl Rng,
    cache_presence: Presence,
    cache_flags: Option<u8>,
    possible_overwrite: bool,
    result_flags: Option<u8>,
    op_result: Result<(), Error>,
) {
    let mut cache = UtxosCache::new_for_test(H256::random().into());
    let (_, outpoint) = insert_single_entry(rng, &mut cache, &cache_presence, cache_flags, None);

    // perform the add_utxo.
    let (utxo, _) = create_utxo(rng, 0);
    let add_result = cache.add_utxo(&outpoint, utxo, possible_overwrite);

    assert_eq!(add_result, op_result);

    if add_result.is_ok() {
        let key = &outpoint;
        let ret_value = cache.utxos.get(key);

        check_flags(ret_value, result_flags, false);
    }
}

/// Checks `spend_utxo` method behaviour.
/// # Arguments
/// `parent_presence` - initial state of the parent cache.
/// `cache_presence` - initial state of the cache.
/// `cache_flags` - The flags of a utxo entry in a cache.
/// `result_flags` - the result ( dirty/not, fresh/not ) after performing `spend_utxo`.
fn check_spend_utxo(
    rng: &mut impl Rng,
    parent_presence: Presence,
    cache_presence: Presence,
    cache_flags: Option<u8>,
    spend_result: Result<(), Error>,
    result_flags: Option<u8>,
) {
    // initialize the parent cache.
    let mut parent = UtxosCache::new_for_test(H256::random().into());
    let (_, parent_outpoint) = insert_single_entry(
        rng,
        &mut parent,
        &parent_presence,
        Some(FRESH | DIRTY),
        None,
    );

    // initialize the child cache
    let mut child = match parent_presence {
        Absent => UtxosCache::new_for_test(H256::random().into()),
        _ => UtxosCache::new(&parent),
    };

    let (_, child_outpoint) = insert_single_entry(
        rng,
        &mut child,
        &cache_presence,
        cache_flags,
        Some(parent_outpoint),
    );

    // perform the spend_utxo
    let res = child.spend_utxo(&child_outpoint);

    assert_eq!(spend_result.map(|_| ()), res.map(|_| ()));

    let key = &child_outpoint;
    let ret_value = child.utxos.get(key);

    check_flags(ret_value, result_flags, true);
}

/// Checks `batch_write` method behaviour.
/// # Arguments
/// `parent_presence` - initial state of the parent cache.
/// `parent_flags` - The flags of a utxo entry in the parent. None if the parent is empty.
/// `child_presence` - To determine whether or not a utxo entry will be written to parent.
/// `child_flags` - The flags of a utxo entry indicated by the `child_presence`. None if presence is Absent.
/// `result` - The result of the parent after performing the `batch_write`.
/// `result_flags` - the pair of `result`, indicating whether it is dirty/not, fresh/not or nothing at all.
fn check_write_utxo(
    rng: &mut impl Rng,
    parent_presence: Presence,
    child_presence: Presence,
    result: Result<Presence, Error>,
    parent_flags: Option<u8>,
    child_flags: Option<u8>,
    result_flags: Option<u8>,
) {
    //initialize the parent cache
    let mut parent = UtxosCache::new_for_test(H256::random().into());
    let (_, outpoint) = insert_single_entry(rng, &mut parent, &parent_presence, parent_flags, None);
    let key = &outpoint;

    // prepare the map for batch write.
    let mut single_entry_map = BTreeMap::new();

    // inserts utxo in the map
    if let Some(child_flags) = child_flags {
        let is_fresh = (child_flags & FRESH) == FRESH;
        let is_dirty = (child_flags & DIRTY) == DIRTY;

        match child_presence {
            Absent => {
                panic!("Please use `Present` or `Spent` presence when child flags are specified.");
            }
            Present => {
                let (utxo, _) = create_utxo(rng, 0);
                let entry = UtxoEntry::new(utxo, is_fresh, is_dirty);
                single_entry_map.insert(key.clone(), entry);
            }
            Spent => {
                let entry = UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty,
                    is_fresh,
                };
                single_entry_map.insert(key.clone(), entry);
            }
        }
    }

    // perform batch write
    let single_entry_cache = ConsumedUtxoCache {
        container: single_entry_map,
        best_block: Id::new(H256::random()),
    };
    let res = parent.batch_write(single_entry_cache);
    let entry = parent.utxos.get(key);

    match result {
        Ok(result_presence) => {
            match result_presence {
                Absent => {
                    // no need to check for the flags, it's empty.
                    assert!(entry.is_none());
                }
                other => check_flags(entry, result_flags, !(other == Present)),
            }
        }
        Err(e) => {
            assert_eq!(res, Err(e));
        }
    }
}

/// Checks the `get_mut_utxo` method behaviour.
fn check_get_mut_utxo(
    rng: &mut impl Rng,
    parent_presence: Presence,
    cache_presence: Presence,
    result_presence: Presence,
    cache_flags: Option<u8>,
    result_flags: Option<u8>,
) {
    let mut parent = UtxosCache::new_for_test(H256::random().into());
    let (parent_utxo, parent_outpoint) = insert_single_entry(
        rng,
        &mut parent,
        &parent_presence,
        Some(FRESH | DIRTY),
        None,
    );

    let mut child = match parent_presence {
        Absent => UtxosCache::new_for_test(H256::random().into()),
        _ => UtxosCache::new(&parent),
    };
    let (child_utxo, child_outpoint) = insert_single_entry(
        rng,
        &mut child,
        &cache_presence,
        cache_flags,
        Some(parent_outpoint),
    );
    let key = &child_outpoint;

    let mut expected_utxo: Option<Utxo> = None;
    {
        // perform the get_mut_utxo
        let utxo_opt = child.get_mut_utxo(&child_outpoint);

        if let Some(utxo) = utxo_opt {
            match cache_presence {
                Absent => {
                    // utxo should be similar to the parent's.
                    assert_eq!(&parent_utxo, utxo);
                }
                _ => {
                    // utxo should be similar to the child's.
                    assert_eq!(&child_utxo, utxo);
                }
            }

            // let's try to update the utxo.
            let old_height_num = match utxo.source_height() {
                UtxoSource::BlockChain(h) => h,
                UtxoSource::MemPool => panic!("Unexpected arm"),
            };
            let new_height_num =
                old_height_num.checked_add(1).expect("should be able to increment");
            let new_height = UtxoSource::BlockChain(new_height_num);

            utxo.set_height(new_height.clone());
            assert_eq!(new_height, *utxo.source_height());
            assert_eq!(
                new_height_num,
                utxo.source_height().blockchain_height().expect("Must be a height")
            );
            expected_utxo = Some(utxo.clone());
        }
    }

    let entry = child.utxos.get(key);
    match result_presence {
        Absent => {
            assert!(entry.is_none());
        }
        other => {
            // check whether the update actually happened.
            if let Some(expected_utxo) = expected_utxo {
                let actual_utxo_entry = &entry.expect("should have an existing entry");
                let actual_utxo = actual_utxo_entry.utxo().expect("should have an existing utxo.");
                assert_eq!(expected_utxo, actual_utxo);
            }
            check_flags(entry, result_flags, !(other == Present))
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn add_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                             CACHE      CACHE Flags      Possible    RESULT flags       RESULT of `add_utxo` method
                             PRESENCE                    Overwrite
    */
    check_add_utxo(&mut rng, Absent,    None,               false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(&mut rng, Absent,    None,               true,   Some(DIRTY),         Ok(()));

    check_add_utxo(&mut rng, Spent,     Some(0),            false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(&mut rng, Spent,     Some(0),            true,   Some(DIRTY),         Ok(()));

    check_add_utxo(&mut rng, Spent,     Some(FRESH),        false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(&mut rng, Spent,     Some(FRESH),        true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(&mut rng, Spent,     Some(DIRTY),        false,  Some(DIRTY),         Ok(()));
    check_add_utxo(&mut rng, Spent,     Some(DIRTY),        true,   Some(DIRTY),         Ok(()));

    check_add_utxo(&mut rng, Spent,     Some(FRESH | DIRTY),false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(&mut rng, Spent,     Some(FRESH | DIRTY),true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(&mut rng, Present,   Some(0),            false,  None,                Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present,   Some(0),            true,   Some(DIRTY),         Ok(()));

    check_add_utxo(&mut rng, Present,   Some(FRESH),        false,  None,                Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present,   Some(FRESH),        true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(&mut rng, Present,   Some(DIRTY),        false,  None,                Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present,   Some(DIRTY),        true,   Some(DIRTY),         Ok(()));

    check_add_utxo(&mut rng, Present,   Some(FRESH | DIRTY), false, None,                Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present,   Some(FRESH | DIRTY), true,  Some(FRESH | DIRTY), Ok(()));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn spend_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                              PARENT     CACHE
                              PRESENCE   PRESENCE  CACHE Flags          RESULT                       RESULT Flags
    */
    check_spend_utxo(&mut rng, Absent,  Absent,   None,                Err(Error::NoUtxoFound),      None);
    check_spend_utxo(&mut rng, Absent,  Spent,    Some(0),             Err(Error::UtxoAlreadySpent), Some(DIRTY));
    check_spend_utxo(&mut rng, Absent,  Spent,    Some(FRESH),         Err(Error::UtxoAlreadySpent), None);
    check_spend_utxo(&mut rng, Absent,  Spent,    Some(DIRTY),         Err(Error::UtxoAlreadySpent), Some(DIRTY));
    check_spend_utxo(&mut rng, Absent,  Spent,    Some(FRESH | DIRTY), Err(Error::UtxoAlreadySpent), None);
    check_spend_utxo(&mut rng, Absent,  Present,  Some(0),             Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Absent,  Present,  Some(FRESH),         Ok(()), None);
    check_spend_utxo(&mut rng, Absent,  Present,  Some(DIRTY),         Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Absent,  Present,  Some(FRESH | DIRTY), Ok(()), None);
    // this should fail, since there's nothing to remove.
    check_spend_utxo(&mut rng, Spent,   Absent,   None,                Err(Error::NoUtxoFound),      None);
    check_spend_utxo(&mut rng, Spent,   Spent,    Some(0),             Err(Error::UtxoAlreadySpent), Some(DIRTY));
    // this should fail, as there's nothing to remove.
    check_spend_utxo(&mut rng, Spent,   Absent,   Some(FRESH),         Err(Error::NoUtxoFound),      None);
    check_spend_utxo(&mut rng, Spent,   Spent,    Some(DIRTY),         Err(Error::UtxoAlreadySpent), Some(DIRTY));
    check_spend_utxo(&mut rng, Spent,   Spent,    Some(FRESH | DIRTY), Err(Error::UtxoAlreadySpent), None);
    check_spend_utxo(&mut rng, Spent,   Present,  Some(0),             Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Spent,   Present,  Some(FRESH),         Ok(()), None);
    check_spend_utxo(&mut rng, Spent,   Present,  Some(DIRTY),         Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Spent,   Present,  Some(FRESH | DIRTY), Ok(()), None);
    check_spend_utxo(&mut rng, Present, Absent,   None,                Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Present, Spent,    Some(0),             Err(Error::UtxoAlreadySpent), Some(DIRTY));
    check_spend_utxo(&mut rng, Present, Spent,    Some(FRESH),         Err(Error::UtxoAlreadySpent), None);
    check_spend_utxo(&mut rng, Present, Spent,    Some(DIRTY),         Err(Error::UtxoAlreadySpent), Some(DIRTY));
    check_spend_utxo(&mut rng, Present, Spent,    Some(FRESH | DIRTY), Err(Error::UtxoAlreadySpent), None);
    check_spend_utxo(&mut rng, Present, Present,  Some(0),             Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Present, Present,  Some(FRESH),         Ok(()), None);
    check_spend_utxo(&mut rng, Present, Present,  Some(DIRTY),         Ok(()), Some(DIRTY));
    check_spend_utxo(&mut rng, Present, Present,  Some(FRESH | DIRTY), Ok(()), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn batch_write_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                              PARENT     CACHE     RESULT
                              PRESENCE   PRESENCE  PRESENCE          PARENT Flags          CACHE Flags          RESULT Flags
    */
    check_write_utxo(&mut rng, Absent, Absent,   Ok(Absent),                  None,                None,                None);
    check_write_utxo(&mut rng, Absent, Spent ,   Ok(Spent),                   None,                Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Absent, Spent ,   Ok(Absent),                  None,                Some(FRESH | DIRTY), None );
    check_write_utxo(&mut rng, Absent, Present,  Ok(Present),                 None,                Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Absent, Present,  Ok(Present),                 None,                Some(FRESH | DIRTY), Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Spent , Absent,   Ok(Spent),                   Some(0),             None,                Some(0));
    check_write_utxo(&mut rng, Spent , Absent,   Ok(Spent),                   Some(FRESH),         None,                Some(FRESH));
    check_write_utxo(&mut rng, Spent , Absent,   Ok(Spent),                   Some(DIRTY),         None,                Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Absent,   Ok(Spent),                   Some(FRESH | DIRTY), None,                Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Spent),                   Some(0),             Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Spent),                   Some(0),             Some(FRESH | DIRTY), Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Absent),                  Some(FRESH),         Some(DIRTY),         None);
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Absent),                  Some(FRESH),         Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Spent),                   Some(DIRTY),         Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Spent),                   Some(DIRTY),         Some(FRESH | DIRTY), Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Absent),                  Some(FRESH | DIRTY), Some(DIRTY),         None);
    check_write_utxo(&mut rng, Spent , Spent ,   Ok(Absent),                  Some(FRESH | DIRTY), Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(0),             Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(0),             Some(FRESH | DIRTY), Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(FRESH),         Some(DIRTY),         Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(FRESH),         Some(FRESH | DIRTY), Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(DIRTY),         Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(DIRTY),         Some(FRESH | DIRTY), Some(DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(FRESH | DIRTY), Some(DIRTY),         Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Spent , Present,  Ok(Present),                 Some(FRESH | DIRTY), Some(FRESH | DIRTY), Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Present, Absent,  Ok(Present),                 Some(0),             None,                Some(0));
    check_write_utxo(&mut rng, Present, Absent,  Ok(Present),                 Some(FRESH),         None,                Some(FRESH));
    check_write_utxo(&mut rng, Present, Absent,  Ok(Present),                 Some(DIRTY),         None,                Some(DIRTY));
    check_write_utxo(&mut rng, Present, Absent,  Ok(Present),                 Some(FRESH | DIRTY), None ,               Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Present, Spent ,  Ok(Spent),                   Some(0),             Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Present, Spent ,  Err(FreshUtxoAlreadyExists), Some(0),             Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Spent ,  Ok(Absent),                  Some(FRESH),         Some(DIRTY),         None);
    check_write_utxo(&mut rng, Present, Spent ,  Err(FreshUtxoAlreadyExists), Some(FRESH),         Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Spent ,  Ok(Spent),                   Some(DIRTY),         Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Present, Spent ,  Err(FreshUtxoAlreadyExists), Some(DIRTY),         Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Spent ,  Ok(Absent),                  Some(FRESH | DIRTY), Some(DIRTY),         None);
    check_write_utxo(&mut rng, Present, Spent ,  Err(FreshUtxoAlreadyExists), Some(FRESH | DIRTY), Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Present, Ok(Present),                 Some(0),             Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Present, Present, Err(FreshUtxoAlreadyExists), Some(0),             Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Present, Ok(Present),                 Some(FRESH),         Some(DIRTY),         Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Present, Present, Err(FreshUtxoAlreadyExists), Some(FRESH),         Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Present, Ok(Present),                 Some(DIRTY),         Some(DIRTY),         Some(DIRTY));
    check_write_utxo(&mut rng, Present, Present, Err(FreshUtxoAlreadyExists), Some(DIRTY),         Some(FRESH | DIRTY), None);
    check_write_utxo(&mut rng, Present, Present, Ok(Present),                 Some(FRESH | DIRTY), Some(DIRTY),         Some(FRESH | DIRTY));
    check_write_utxo(&mut rng, Present, Present, Err(FreshUtxoAlreadyExists), Some(FRESH | DIRTY), Some(FRESH | DIRTY), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn access_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                               PARENT     CACHE     RESULT     CACHE
                               PRESENCE   PRESENCE  PRESENCE   Flags        RESULT Flags
    */
    check_get_mut_utxo(&mut rng, Absent, Absent, Absent,   None,               None);
    check_get_mut_utxo(&mut rng, Absent, Spent , Spent ,   Some(0),            Some(0));
    check_get_mut_utxo(&mut rng, Absent, Spent , Spent ,   Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(&mut rng, Absent, Spent , Spent ,   Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(&mut rng, Absent, Spent , Spent ,   Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(&mut rng, Absent, Present, Present, Some(0),            Some(0));
    check_get_mut_utxo(&mut rng, Absent, Present, Present, Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(&mut rng, Absent, Present, Present, Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(&mut rng, Absent, Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(&mut rng, Spent , Absent, Absent,   None,               None);
    check_get_mut_utxo(&mut rng, Spent , Spent , Spent ,   Some(0),            Some(0));
    check_get_mut_utxo(&mut rng, Spent , Spent , Spent ,   Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(&mut rng, Spent , Spent , Spent ,   Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(&mut rng, Spent , Spent , Spent ,   Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(&mut rng, Spent , Present, Present, Some(0),            Some(0));
    check_get_mut_utxo(&mut rng, Spent , Present, Present, Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(&mut rng, Spent , Present, Present, Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(&mut rng, Spent , Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(&mut rng, Present, Absent, Present, None,               Some(0));
    check_get_mut_utxo(&mut rng, Present, Spent , Spent ,  Some(0),            Some(0));
    check_get_mut_utxo(&mut rng, Present, Spent , Spent ,  Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(&mut rng, Present, Spent , Spent ,  Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(&mut rng, Present, Spent , Spent ,  Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some(0),           Some(0));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some(FRESH),       Some(FRESH));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some(DIRTY),       Some(DIRTY));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn derive_cache_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut cache = UtxosCache::new_for_test(H256::random().into());

    let (utxo, outpoint_1) = create_utxo(&mut rng, 10);
    assert!(cache.add_utxo(&outpoint_1, utxo, false).is_ok());

    let (utxo, outpoint_2) = create_utxo(&mut rng, 20);
    assert!(cache.add_utxo(&outpoint_2, utxo, false).is_ok());

    let mut extra_cache = cache.derive_cache();
    assert!(extra_cache.utxos.is_empty());

    assert!(extra_cache.has_utxo(&outpoint_1));
    assert!(extra_cache.has_utxo(&outpoint_2));

    let (utxo, outpoint) = create_utxo(&mut rng, 30);
    assert!(extra_cache.add_utxo(&outpoint, utxo, true).is_ok());

    assert!(!cache.has_utxo(&outpoint));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn blockchain_or_mempool_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut cache = UtxosCache::new_for_test(H256::random().into());

    let (utxo, outpoint_1) = create_utxo(&mut rng, 10);
    assert!(cache.add_utxo(&outpoint_1, utxo, false).is_ok());

    let (utxo, outpoint_2) = create_utxo_for_mempool(&mut rng);
    assert!(cache.add_utxo(&outpoint_2, utxo, false).is_ok());

    let res = cache.utxo(&outpoint_2).expect("should contain utxo");
    assert!(res.source_height().is_mempool());
    assert_eq!(res.source, UtxoSource::MemPool);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn multiple_update_utxos_test(#[case] seed: Seed) {
    use common::chain::signature::inputsig::InputWitness;

    let mut rng = make_seedable_rng(seed);
    let mut cache = UtxosCache::new_for_test(H256::random().into());

    // let's test `add_utxos`
    let tx = Transaction::new(0x00, vec![], create_tx_outputs(&mut rng, 10), 0x01).unwrap();
    assert!(cache.add_utxos(&tx, UtxoSource::BlockChain(BlockHeight::new(2)), false).is_ok());

    // check that the outputs of tx are added in the cache.
    tx.outputs().iter().enumerate().for_each(|(i, x)| {
        let id = OutPointSourceId::from(tx.get_id());
        let outpoint = OutPoint::new(id, i as u32);

        let utxo = cache.utxo(&outpoint).expect("utxo should exist");
        assert_eq!(utxo.output(), x);
    });

    // let's spend some outputs.;
    // randomly take half of the outputs to spend.
    let results =
        seq::index::sample(&mut rng, tx.outputs().len(), tx.outputs().len() / 2).into_vec();
    let to_spend = results
        .into_iter()
        .map(|idx| {
            let id = OutPointSourceId::from(tx.get_id());
            TxInput::new(id, idx as u32, InputWitness::NoSignature(None))
        })
        .collect_vec();

    // create a new transaction
    let new_tx = Transaction::new(0x00, to_spend.clone(), vec![], 0).expect("should succeed");
    // let's test `spend_utxos`
    let tx_undo = cache.spend_utxos(&new_tx, BlockHeight::new(2)).expect("should return txundo");

    // check that these utxos came from the tx's output
    tx_undo.inner().iter().for_each(|x| {
        assert!(tx.outputs().contains(x.output()));
    });

    // check that the spent utxos should not exist in the cache anymore.
    to_spend.iter().for_each(|input| {
        assert!(cache.utxo(input.outpoint()).is_none());
    });
}

#[test]
fn check_best_block_after_flush() {
    let mut cache1 = UtxosCache::new_for_test(H256::random().into());
    let cache2 = UtxosCache::new_for_test(H256::random().into());
    assert_ne!(cache1.best_block_hash(), cache2.best_block_hash());
    let expected_hash = cache2.best_block_hash();
    assert!(flush_to_base(cache2, &mut cache1).is_ok());
    assert_eq!(expected_hash, cache1.best_block_hash());
}
