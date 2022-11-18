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

pub mod simulation;
pub mod simulation_with_undo;
pub mod test_helper;

pub struct EmptyUtxosView {
    best_block_hash: Id<GenBlock>,
}

impl UtxosView for EmptyUtxosView {
    fn utxo(&self, _outpoint: &OutPoint) -> Option<Utxo> {
        None
    }

    fn has_utxo(&self, _outpoint: &OutPoint) -> bool {
        false
    }

    fn best_block_hash(&self) -> Id<GenBlock> {
        self.best_block_hash
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

pub fn empty_test_utxos_view(best_block_hash: Id<GenBlock>) -> Box<dyn UtxosView> {
    Box::new(EmptyUtxosView { best_block_hash })
}

use crate::{
    flush_to_base,
    tests::test_helper::{
        create_tx_outputs,
        Presence::{self, *},
    },
    utxo_entry::{IsDirty, IsFresh, UtxoEntry},
    ConsumedUtxoCache,
    Error::{self, *},
    FlushableUtxoView, Utxo, UtxoSource, UtxosCache, UtxosTxUndo, UtxosView,
};
use common::{
    chain::{
        block::{
            consensus_data::{PoSData, PoWData},
            timestamp::BlockTimestamp,
            Block, BlockReward, ConsensusData,
        },
        signature::inputsig::InputWitness,
        tokens::OutputValue,
        Destination, GenBlock, OutPoint, OutPointSourceId, OutputPurpose, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, BlockHeight, Compact, Id, Idable, H256},
};
use crypto::random::{seq, CryptoRng, Rng};
use itertools::Itertools;
use rstest::rstest;
use std::collections::BTreeMap;
use test_utils::random::{make_seedable_rng, Seed};

/// Checks `add_utxo` method behavior.
/// # Arguments
/// `cache_presence` - initial state of the cache
/// `cache_flags` - The flags of the existing utxo entry for testing
/// `possible_overwrite` - to set the `possible_overwrite` of the `add_utxo` method
/// `result_flags` - the result ( dirty/not, fresh/not ) after calling the `add_utxo` method.
/// `op_result` - the result of calling `add_utxo` method, whether it succeeded or not.
fn check_add_utxo(
    rng: &mut (impl Rng + CryptoRng),
    cache_presence: Presence,
    cache_flags: Option<(IsFresh, IsDirty)>,
    possible_overwrite: bool,
    result_flags: Option<(IsFresh, IsDirty)>,
    op_result: Result<(), Error>,
) {
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);
    let (_, outpoint) =
        test_helper::insert_single_entry(rng, &mut cache, cache_presence, cache_flags, None);

    // perform the add_utxo.
    let (utxo, _) = test_helper::create_utxo(rng, 0);
    let add_result = cache.add_utxo(&outpoint, utxo, possible_overwrite);

    assert_eq!(add_result, op_result);

    if add_result.is_ok() {
        let key = &outpoint;
        let ret_value = cache.utxos.get(key);

        test_helper::check_flags(ret_value, result_flags, false);
    }
}

/// Checks `spend_utxo` method behavior.
/// # Arguments
/// `parent_presence` - initial state of the parent cache.
/// `cache_presence` - initial state of the cache.
/// `cache_flags` - The flags of a utxo entry in a cache.
/// `result_flags` - the result ( dirty/not, fresh/not ) after performing `spend_utxo`.
fn check_spend_utxo(
    rng: &mut (impl Rng + CryptoRng),
    parent_presence: Presence,
    cache_presence: Presence,
    cache_flags: Option<(IsFresh, IsDirty)>,
    mut spend_result: Result<(), Error>,
    result_flags: Option<(IsFresh, IsDirty)>,
) {
    // initialize the parent cache.
    let mut parent = UtxosCache::from_owned_parent(empty_test_utxos_view(H256::zero().into()));
    let (_, parent_outpoint) = test_helper::insert_single_entry(
        rng,
        &mut parent,
        parent_presence,
        // parent flags are irrelevant, but this combination can be used for both spent/unspent
        Some((IsFresh::No, IsDirty::Yes)),
        None,
    );

    // initialize the child cache
    let mut child = match parent_presence {
        Absent => UtxosCache::from_owned_parent(empty_test_utxos_view(H256::zero().into())),
        _ => {
            let parent: Box<dyn UtxosView> = Box::new(parent);
            UtxosCache::from_owned_parent(parent)
        }
    };

    let (_, child_outpoint) = test_helper::insert_single_entry(
        rng,
        &mut child,
        cache_presence,
        cache_flags,
        Some(parent_outpoint),
    );

    // patch the spend result in case it's a double spend with proper outpoint
    // which cannot be known beforehand
    spend_result = spend_result.map_err(|err| match err {
        UtxoAlreadySpent(_) => UtxoAlreadySpent(child_outpoint.tx_id()),
        _ => err,
    });

    // perform the spend_utxo
    let res = child.spend_utxo(&child_outpoint);

    assert_eq!(spend_result.map(|_| ()), res.map(|_| ()));

    let key = &child_outpoint;
    let ret_value = child.utxos.get(key);

    test_helper::check_flags(ret_value, result_flags, true);
}

/// Checks `batch_write` method behavior.
/// # Arguments
/// `parent_presence` - initial state of the parent cache.
/// `parent_flags` - The flags of a utxo entry in the parent. None if the parent is empty.
/// `child_presence` - To determine whether or not a utxo entry will be written to parent.
/// `child_flags` - The flags of a utxo entry indicated by the `child_presence`. None if presence is Absent.
/// `result` - The result of the parent after performing the `batch_write`.
/// `result_flags` - the pair of `result`, indicating whether it is dirty/not, fresh/not or nothing at all.
fn check_write_utxo(
    rng: &mut (impl Rng + CryptoRng),
    parent_presence: Presence,
    child_presence: Presence,
    result: Result<Presence, Error>,
    parent_flags: Option<(IsFresh, IsDirty)>,
    child_flags: Option<(IsFresh, IsDirty)>,
    result_flags: Option<(IsFresh, IsDirty)>,
) {
    //initialize the parent cache
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut parent = UtxosCache::from_borrowed_parent(&test_view);
    let (_, outpoint) =
        test_helper::insert_single_entry(rng, &mut parent, parent_presence, parent_flags, None);
    let key = &outpoint;

    // prepare the map for batch write.
    let mut single_entry_map = BTreeMap::new();

    // inserts utxo in the map
    if let Some((is_fresh, is_dirty)) = child_flags {
        match child_presence {
            Absent => {
                panic!("Please use `Present` or `Spent` presence when child flags are specified.");
            }
            Present => {
                let (utxo, _) = test_helper::create_utxo(rng, 0);
                let entry = UtxoEntry::new(Some(utxo), is_fresh, is_dirty);
                single_entry_map.insert(key.clone(), entry);
            }
            Spent => {
                let entry = UtxoEntry::new(None, is_fresh, is_dirty);
                single_entry_map.insert(key.clone(), entry);
            }
        }
    }

    // perform batch write
    let single_entry_cache = ConsumedUtxoCache {
        container: single_entry_map,
        best_block: Id::new(H256::random_using(rng)),
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
                other => test_helper::check_flags(entry, result_flags, !(other == Present)),
            }
        }
        Err(e) => {
            assert_eq!(res, Err(e));
        }
    }
}

/// Checks the `get_mut_utxo` method behavior.
fn check_get_mut_utxo(
    rng: &mut (impl Rng + CryptoRng),
    parent_presence: Presence,
    cache_presence: Presence,
    result_presence: Presence,
    cache_flags: Option<(IsFresh, IsDirty)>,
    result_flags: Option<(IsFresh, IsDirty)>,
) {
    let mut parent = UtxosCache::from_owned_parent(empty_test_utxos_view(H256::zero().into()));
    let (parent_utxo, parent_outpoint) = test_helper::insert_single_entry(
        rng,
        &mut parent,
        parent_presence,
        // parent flags are irrelevant, but this combination can be used for both spent/unspent
        Some((IsFresh::No, IsDirty::Yes)),
        None,
    );

    let mut child = match parent_presence {
        Absent => UtxosCache::from_owned_parent(empty_test_utxos_view(H256::zero().into())),
        _ => {
            let parent: Box<dyn UtxosView> = Box::new(parent);
            UtxosCache::from_owned_parent(parent)
        }
    };
    let (child_utxo, child_outpoint) = test_helper::insert_single_entry(
        rng,
        &mut child,
        cache_presence,
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
            let old_height_num = match utxo.source() {
                UtxoSource::Blockchain(h) => h,
                UtxoSource::Mempool => panic!("Unexpected arm"),
            };
            let new_height_num =
                old_height_num.checked_add(1).expect("should be able to increment");
            let new_height = UtxoSource::Blockchain(new_height_num);

            utxo.set_height(new_height.clone());
            assert_eq!(new_height, *utxo.source());
            assert_eq!(
                new_height_num,
                utxo.source().blockchain_height().expect("Must be a height")
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
                assert_eq!(expected_utxo, *actual_utxo);
            }
            test_helper::check_flags(entry, result_flags, !(other == Present))
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
                             CACHE      CACHE Flags                       Possible    RESULT flags                RESULT of `add_utxo` method
                             PRESENCE                                     Overwrite
    */
    check_add_utxo(&mut rng, Absent,  None,                               false, Some((IsFresh::Yes, IsDirty::Yes)), Ok(()));
    check_add_utxo(&mut rng, Absent,  None,                               true,  Some((IsFresh::No, IsDirty::Yes)),  Ok(()));

    check_add_utxo(&mut rng, Spent,   Some((IsFresh::Yes, IsDirty::No)),  false, Some((IsFresh::Yes, IsDirty::Yes)), Ok(()));
    check_add_utxo(&mut rng, Spent,   Some((IsFresh::Yes, IsDirty::No)),  true,  Some((IsFresh::Yes, IsDirty::Yes)), Ok(()));

    check_add_utxo(&mut rng, Spent,   Some((IsFresh::No, IsDirty::Yes)),  false, Some((IsFresh::No, IsDirty::Yes)),  Ok(()));
    check_add_utxo(&mut rng, Spent,   Some((IsFresh::No, IsDirty::Yes)),  true,  Some((IsFresh::No, IsDirty::Yes)),  Ok(()));

    check_add_utxo(&mut rng, Present, Some((IsFresh::No, IsDirty::No)),   false, None,                               Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present, Some((IsFresh::No, IsDirty::No)),   true,  Some((IsFresh::No, IsDirty::Yes)),  Ok(()));

    check_add_utxo(&mut rng, Present, Some((IsFresh::No, IsDirty::Yes)),  false, None,                               Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present, Some((IsFresh::No, IsDirty::Yes)),  true,  Some((IsFresh::No, IsDirty::Yes)),  Ok(()));

    check_add_utxo(&mut rng, Present, Some((IsFresh::Yes, IsDirty::Yes)), false, None,                               Err(OverwritingUtxo));
    check_add_utxo(&mut rng, Present, Some((IsFresh::Yes, IsDirty::Yes)), true,  Some((IsFresh::Yes, IsDirty::Yes)), Ok(()));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn spend_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    // just a dummy id for the compiler
    let id = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));
    /*
                              PARENT     CACHE
                              PRESENCE   PRESENCE  CACHE Flags          RESULT                       RESULT Flags
    */
    check_spend_utxo(&mut rng, Absent,  Absent,  None,                               Err(Error::NoUtxoFound),                  None);
    check_spend_utxo(&mut rng, Absent,  Spent,   Some((IsFresh::Yes, IsDirty::No)),  Err(Error::UtxoAlreadySpent(id.clone())), None);
    check_spend_utxo(&mut rng, Absent,  Spent,   Some((IsFresh::No, IsDirty::Yes)),  Err(Error::UtxoAlreadySpent(id.clone())), Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Absent,  Present, Some((IsFresh::No, IsDirty::No)),   Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Absent,  Present, Some((IsFresh::No, IsDirty::Yes)),  Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Absent,  Present, Some((IsFresh::Yes, IsDirty::Yes)), Ok(()),                                   None);
    check_spend_utxo(&mut rng, Spent,   Absent,  None,                               Err(Error::NoUtxoFound),                  None);
    check_spend_utxo(&mut rng, Spent,   Absent,  Some((IsFresh::Yes, IsDirty::No)),  Err(Error::NoUtxoFound),                  None);
    check_spend_utxo(&mut rng, Spent,   Present, Some((IsFresh::No, IsDirty::No)),   Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Spent,   Present, Some((IsFresh::No, IsDirty::Yes)),  Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Spent,   Present, Some((IsFresh::Yes, IsDirty::Yes)), Ok(()),                                   None);
    check_spend_utxo(&mut rng, Present, Absent,  None,                               Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Present, Spent,   Some((IsFresh::Yes, IsDirty::No)),  Err(Error::UtxoAlreadySpent(id.clone())), None);
    check_spend_utxo(&mut rng, Present, Spent,   Some((IsFresh::No, IsDirty::Yes)),  Err(Error::UtxoAlreadySpent(id)),         Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Present, Present, Some((IsFresh::No, IsDirty::No)),   Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Present, Present, Some((IsFresh::No, IsDirty::Yes)),  Ok(()),                                   Some((IsFresh::No, IsDirty::Yes)));
    check_spend_utxo(&mut rng, Present, Present, Some((IsFresh::Yes, IsDirty::Yes)), Ok(()),                                   None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn batch_write_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                              PARENT     CACHE     RESULT
                              PRESENCE   PRESENCE  PRESENCE                    PARENT Flags                        CACHE Flags                          RESULT Flags
    */
    check_write_utxo(&mut rng, Absent,  Absent,   Ok(Absent),                  None,                               None,                               None);
    check_write_utxo(&mut rng, Absent,  Spent ,   Ok(Spent),                   None,                               Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Absent,  Present,  Ok(Present),                 None,                               Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Absent,  Present,  Ok(Present),                 None,                               Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Absent,   Ok(Spent),                   Some((IsFresh::Yes, IsDirty::No)),  None,                               Some((IsFresh::Yes, IsDirty::No)));
    check_write_utxo(&mut rng, Spent ,  Absent,   Ok(Spent),                   Some((IsFresh::No, IsDirty::Yes)),  None,                               Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Spent ,   Ok(Absent),                  Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::No, IsDirty::Yes)),  None);
    check_write_utxo(&mut rng, Spent ,  Spent ,   Ok(Spent),                   Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Present,  Ok(Present),                 Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::Yes, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Present,  Ok(Present),                 Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Present,  Ok(Present),                 Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Spent ,  Present,  Ok(Present),                 Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Absent,   Ok(Present),                 Some((IsFresh::No, IsDirty::No)),   None,                               Some((IsFresh::No, IsDirty::No)));
    check_write_utxo(&mut rng, Present, Absent,   Ok(Present),                 Some((IsFresh::No, IsDirty::Yes)),  None,                               Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Absent,   Ok(Present),                 Some((IsFresh::Yes, IsDirty::Yes)), None ,                              Some((IsFresh::Yes, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Spent ,   Ok(Spent),                   Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Spent ,   Ok(Spent),                   Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Spent ,   Ok(Absent),                  Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::No, IsDirty::Yes)),  None);
    check_write_utxo(&mut rng, Present, Present,  Ok(Present),                 Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Present,  Err(FreshUtxoAlreadyExists), Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::Yes, IsDirty::Yes)), None);
    check_write_utxo(&mut rng, Present, Present,  Ok(Present),                 Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Present,  Err(FreshUtxoAlreadyExists), Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::Yes, IsDirty::Yes)), None);
    check_write_utxo(&mut rng, Present, Present,  Ok(Present),                 Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::Yes, IsDirty::Yes)));
    check_write_utxo(&mut rng, Present, Present,  Err(FreshUtxoAlreadyExists), Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[rustfmt::skip]
fn access_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    /*
                               PARENT     CACHE     RESULT     CACHE
                               PRESENCE   PRESENCE  PRESENCE   Flags                            RESULT Flags
    */
    check_get_mut_utxo(&mut rng, Absent,  Absent,  Absent,  None,                               None);
    check_get_mut_utxo(&mut rng, Absent,  Spent ,  Spent ,  Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::Yes, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Absent,  Spent ,  Spent ,  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Absent,  Present, Present, Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::No, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Absent,  Present, Present, Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Absent,  Present, Present, Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Spent ,  Absent,  Absent,  None,                               None);
    check_get_mut_utxo(&mut rng, Spent ,  Spent ,  Spent ,  Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::Yes, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Spent ,  Spent ,  Spent ,  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Spent ,  Present, Present, Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::No, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Spent ,  Present, Present, Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Spent ,  Present, Present, Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Present, Absent,  Present, None,                               Some((IsFresh::No, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Present, Spent ,  Spent ,  Some((IsFresh::Yes, IsDirty::No)),  Some((IsFresh::Yes, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Present, Spent ,  Spent ,  Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some((IsFresh::No, IsDirty::No)),   Some((IsFresh::No, IsDirty::No)));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some((IsFresh::No, IsDirty::Yes)),  Some((IsFresh::No, IsDirty::Yes)));
    check_get_mut_utxo(&mut rng, Present, Present, Present, Some((IsFresh::Yes, IsDirty::Yes)), Some((IsFresh::Yes, IsDirty::Yes)));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn derive_cache_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    let (utxo, outpoint_1) = test_helper::create_utxo(&mut rng, 10);
    assert!(cache.add_utxo(&outpoint_1, utxo, false).is_ok());

    let (utxo, outpoint_2) = test_helper::create_utxo(&mut rng, 20);
    assert!(cache.add_utxo(&outpoint_2, utxo, false).is_ok());

    let mut extra_cache = UtxosCache::from_borrowed_parent(&cache);
    assert!(extra_cache.utxos.is_empty());

    assert!(extra_cache.has_utxo(&outpoint_1));
    assert!(extra_cache.has_utxo(&outpoint_2));

    let (utxo, outpoint) = test_helper::create_utxo(&mut rng, 30);
    assert!(extra_cache.add_utxo(&outpoint, utxo, true).is_ok());

    assert!(!cache.has_utxo(&outpoint));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn blockchain_or_mempool_utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    let (utxo, outpoint_1) = test_helper::create_utxo(&mut rng, 10);
    assert!(cache.add_utxo(&outpoint_1, utxo, false).is_ok());

    let (utxo, outpoint_2) = test_helper::create_utxo_for_mempool(&mut rng);
    assert!(cache.add_utxo(&outpoint_2, utxo, false).is_ok());

    let res = cache.utxo(&outpoint_2).expect("should contain utxo");
    assert!(res.source().is_mempool());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn multiple_update_utxos_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // let's test `add_utxos`
    let tx = Transaction::new(
        0x00,
        vec![],
        test_helper::create_tx_outputs(&mut rng, 10),
        0x01,
    )
    .unwrap();
    assert!(cache
        .add_utxos_from_tx(&tx, UtxoSource::Blockchain(BlockHeight::new(2)), false)
        .is_ok());

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
            TxInput::new(id, idx as u32)
        })
        .collect_vec();

    // create a new transaction
    let new_tx = Transaction::new(0x00, to_spend.clone(), vec![], 0).expect("should succeed");
    // let's test `connect_transaction`
    let tx_undo = cache
        .connect_transaction(&new_tx, BlockHeight::new(2))
        .expect("should return tx undo");

    // check that these utxos came from the tx's output
    tx_undo.utxos().iter().for_each(|x| {
        assert!(tx.outputs().contains(x.output()));
    });

    // check that the spent utxos should not exist in the cache anymore.
    to_spend.iter().for_each(|input| {
        assert!(cache.utxo(input.outpoint()).is_none());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_best_block_after_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view1 = empty_test_utxos_view(H256::random_using(&mut rng).into());
    let test_view2 = empty_test_utxos_view(H256::random_using(&mut rng).into());
    let mut cache1 = UtxosCache::from_borrowed_parent(&test_view1);
    let cache2 = UtxosCache::from_borrowed_parent(&test_view2);
    assert_ne!(cache1.best_block_hash(), cache2.best_block_hash());
    let expected_hash = cache2.best_block_hash();
    assert!(flush_to_base(cache2, &mut cache1).is_ok());
    assert_eq!(expected_hash, cache1.best_block_hash());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_add_utxos_from_block_reward(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    let block_reward = BlockReward::new(test_helper::create_tx_outputs(&mut rng, 10));

    let block_id = Id::new(H256::random_using(&mut rng));
    assert!(cache
        .add_utxos_from_block_reward(
            &block_reward,
            UtxoSource::Blockchain(BlockHeight::new(2)),
            &block_id,
            false
        )
        .is_ok());

    block_reward.outputs().iter().enumerate().for_each(|(i, x)| {
        let outpoint = OutPoint::new(OutPointSourceId::BlockReward(block_id), i as u32);
        let utxo = cache.utxo(&outpoint).expect("utxo should exist");
        assert_eq!(utxo.output(), x);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_tx_spend_undo_spend(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (utxo, outpoint) = test_helper::create_utxo(&mut rng, 1);
    cache.add_utxo(&outpoint, utxo, false).unwrap();

    // spend the utxo in a transaction
    let input = TxInput::new(outpoint.tx_id(), outpoint.output_index());
    let tx = Transaction::new(0x00, vec![input], create_tx_outputs(&mut rng, 1), 0x01).unwrap();
    let undo1 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.utxos().len() == 1);

    //undo spending
    cache
        .disconnect_transaction(&tx, UtxosTxUndo::new(undo1.utxos().to_owned()))
        .unwrap();
    assert!(cache.has_utxo_in_cache(&outpoint));

    //spend the transaction again
    let undo2 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert_eq!(undo1, undo2);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_burn_spend_undo_spend(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (u, outpoint) = test_helper::create_utxo(&mut rng, 1);
    cache.add_utxo(&outpoint, u, false).unwrap();

    // burn output in a tx
    let output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(10)),
        OutputPurpose::Burn,
    );
    let input = TxInput::new(outpoint.tx_id(), outpoint.output_index());
    let tx = Transaction::new(0x00, vec![input], vec![output], 0x01).unwrap();
    let undo1 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.utxos().len() == 1);

    //undo spending
    cache
        .disconnect_transaction(&tx, UtxosTxUndo::new(undo1.utxos().to_owned()))
        .unwrap();
    assert!(cache.has_utxo_in_cache(&outpoint));

    //spend the transaction again
    let undo2 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert_eq!(undo1, undo2);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_pos_reward_spend_undo_spend(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (utxo, outpoint) = test_helper::create_utxo_from_reward(&mut rng, 1);
    cache.add_utxo(&outpoint, utxo, false).unwrap();

    let inputs = vec![TxInput::new(outpoint.tx_id(), outpoint.output_index())];
    let outputs = create_tx_outputs(&mut rng, 1);

    let block = Block::new(
        vec![],
        Id::new(H256::random_using(&mut rng)),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::PoS(PoSData::new(
            inputs,
            vec![InputWitness::NoSignature(None)],
            Compact(1),
        )),
        BlockReward::new(outputs),
    )
    .unwrap();
    let reward = block.block_reward_transactable();

    // spend the utxo in a block reward
    let undo1 = cache
        .connect_block_transactable(&reward, &block.get_id().into(), BlockHeight::new(1))
        .expect("spend should succeed")
        .expect("block undo should contain value");
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.inner().len() == 1);

    //undo spending
    cache
        .disconnect_block_transactable(&reward, &block.get_id().into(), Some(undo1.clone()))
        .unwrap();
    assert!(cache.has_utxo_in_cache(&outpoint));

    //spend the reward again
    let undo2 = cache
        .connect_block_transactable(&reward, &block.get_id().into(), BlockHeight::new(1))
        .expect("spend should succeed")
        .expect("block undo should contain value");
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert_eq!(undo1, undo2);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_pow_reward_spend_undo_spend(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    let block = Block::new(
        vec![],
        Id::new(H256::random_using(&mut rng)),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::PoW(PoWData::new(Compact(1), 1)),
        BlockReward::new(create_tx_outputs(&mut rng, 1)),
    )
    .unwrap();
    let reward = block.block_reward_transactable();
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(block.get_id().into()), 0);

    // spend the utxo in a block reward
    let undo1 = cache
        .connect_block_transactable(&reward, &block.get_id().into(), BlockHeight::new(1))
        .expect("spend should succeed");
    assert!(cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.is_none());

    //undo spending
    cache
        .disconnect_block_transactable(&reward, &block.get_id().into(), None)
        .unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));

    //spend the reward again
    let undo2 = cache
        .connect_block_transactable(&reward, &block.get_id().into(), BlockHeight::new(1))
        .expect("spend should succeed");
    assert!(cache.has_utxo_in_cache(&outpoint));
    assert!(undo2.is_none());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_missing_reward_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (utxo, outpoint) = test_helper::create_utxo_from_reward(&mut rng, 1);
    cache.add_utxo(&outpoint, utxo, false).unwrap();

    let inputs = vec![TxInput::new(outpoint.tx_id(), outpoint.output_index())];
    let outputs = create_tx_outputs(&mut rng, 1);

    let block = Block::new(
        vec![],
        Id::new(H256::random_using(&mut rng)),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::PoS(PoSData::new(
            inputs,
            vec![InputWitness::NoSignature(None)],
            Compact(1),
        )),
        BlockReward::new(outputs),
    )
    .unwrap();
    let reward = block.block_reward_transactable();

    // spend the utxo in a block reward
    let undo1 = cache
        .connect_block_transactable(&reward, &block.get_id().into(), BlockHeight::new(1))
        .expect("spend should succeed")
        .expect("block undo should contain value");
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.inner().len() == 1);

    //undo spending
    let res = cache.disconnect_block_transactable(&reward, &block.get_id().into(), None);
    assert_eq!(
        res,
        Err(Error::MissingBlockRewardUndo(block.get_id().into()))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_burn_output_in_block_reward(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (utxo, outpoint) = test_helper::create_utxo_from_reward(&mut rng, 1);
    cache.add_utxo(&outpoint, utxo, false).unwrap();

    let inputs = vec![TxInput::new(outpoint.tx_id(), outpoint.output_index())];
    let outputs = vec![TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(10)),
        OutputPurpose::Burn,
    )];

    let block = Block::new(
        vec![],
        Id::new(H256::random_using(&mut rng)),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::PoS(PoSData::new(
            inputs,
            vec![InputWitness::NoSignature(None)],
            Compact(1),
        )),
        BlockReward::new(outputs),
    )
    .unwrap();
    let reward = block.block_reward_transactable();

    // spend the utxo in a block reward
    let block_id = block.get_id().into();
    assert_eq!(
        cache
            .connect_block_transactable(&reward, &block_id, BlockHeight::new(1))
            .unwrap_err(),
        Error::InvalidBlockRewardOutputType(block_id)
    );
}

// This test checks that if burned output is skipped at index 0 it won't influence
// subsequent output at index 1
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_burn_output_indexing(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut cache = UtxosCache::from_borrowed_parent(&test_view);

    // add 1 utxo to the utxo set
    let (u, outpoint) = test_helper::create_utxo(&mut rng, 1);
    cache.add_utxo(&outpoint, u, false).unwrap();

    // create burn output at index 0
    let output1 = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(10)),
        OutputPurpose::Burn,
    );
    // create transfer output at index 1
    let output2 = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(10)),
        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
    );
    let input = TxInput::new(outpoint.tx_id(), outpoint.output_index());
    let tx = Transaction::new(0x00, vec![input], vec![output1, output2], 0x01).unwrap();
    let undo1 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert!(undo1.utxos().len() == 1);

    //undo spending
    cache
        .disconnect_transaction(&tx, UtxosTxUndo::new(undo1.utxos().to_owned()))
        .unwrap();
    assert!(cache.has_utxo_in_cache(&outpoint));

    //spend the transaction again
    let undo2 = cache.connect_transaction(&tx, BlockHeight::new(1)).unwrap();
    assert!(!cache.has_utxo_in_cache(&outpoint));
    assert_eq!(undo1, undo2);
}
