use crate::chainstate::utxo::{OutPointKey, Utxo, UtxoEntry, UtxosCache, UtxosView};
use crate::chainstate::Error::{self, OverwritingUtxo, UtxoAlreadyExists};
use Presence::Absent;
use Presence::Present;
use Presence::Spent;

use std::collections::HashMap;
use crate::utxo::test_helper::{check_flags, create_utxo, insert_single_entry, Presence, DIRTY, FRESH};
use crate::utxo::UtxoStatus;

/// Checks `add_utxo` method behaviour.
/// # Arguments
/// `cache_presence` - initial state of the cache
/// `cache_flags` - The flags of the existing utxo entry for testing
/// `possible_overwrite` - to set the `possible_overwrite` of the `add_utxo` method
/// `result_flags` - the result ( dirty/not, fresh/not ) after calling the `add_utxo` method.
/// `op_result` - the result of calling `add_utxo` method, whether it succeeded or not.
fn check_add_utxo(
    cache_presence: Presence,
    cache_flags: Option<u8>,
    possible_overwrite: bool,
    result_flags: Option<u8>,
    op_result: Result<(), Error>,
) {
    let mut cache = UtxosCache::default();
    let (_, outpoint) = insert_single_entry(&mut cache, &cache_presence, cache_flags, None);

    // perform the add_utxo.
    let (utxo, _) = create_utxo(0);
    let add_result = cache.add_utxo(utxo, &outpoint, possible_overwrite);

    assert_eq!(add_result, op_result);

    if add_result.is_ok() {
        let key = OutPointKey::from(&outpoint);
        let ret_value = cache.utxos.get(&key);

        check_flags(ret_value, result_flags, false);
    }

    println!("the value of the map: {:?}", cache);
}

/// Checks `spend_utxo` method behaviour.
/// # Arguments
/// `parent_presence` - initial state of the parent cache.
/// `cache_presence` - initial state of the cache.
/// `cache_flags` - The flags of a utxo entry in a cache.
/// `result_flags` - the result ( dirty/not, fresh/not ) after performing `spend_utxo`.
fn check_spend_utxo(
    parent_presence: Presence,
    cache_presence: Presence,
    cache_flags: Option<u8>,
    result_flags: Option<u8>,
) -> bool {
    // initialize the parent cache.
    let mut parent = UtxosCache::default();
    let (_, parent_outpoint) =
        insert_single_entry(&mut parent, &parent_presence, Some(FRESH | DIRTY), None);

    // initialize the child cache
    let mut child = match parent_presence {
        Absent => UtxosCache::default(),
        _ => UtxosCache::new(&parent),
    };

    let (_, child_outpoint) = insert_single_entry(
        &mut child,
        &cache_presence,
        cache_flags,
        Some(parent_outpoint),
    );

    // perform the spend_utxo
    let res = child.spend_utxo(&child_outpoint);
    let key = OutPointKey::from(&child_outpoint);
    let ret_value = child.utxos.get(&key);

    check_flags(ret_value, result_flags, true);

    res
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
    parent_presence: Presence,
    child_presence: Presence,
    result: Result<Presence, Error>,
    parent_flags: Option<u8>,
    child_flags: Option<u8>,
    result_flags: Option<u8>,
) {
    //initialize the parent cache
    let mut parent = UtxosCache::default();
    let (_, outpoint) = insert_single_entry(&mut parent, &parent_presence, parent_flags, None);
    let key = OutPointKey::from(&outpoint);

    // prepare the map for batch write.
    let mut single_entry_map = HashMap::new();

    // inserts utxo in the map
    if let Some(child_flags) = child_flags {
        let is_fresh = (child_flags & FRESH) == FRESH;
        let is_dirty = (child_flags & DIRTY) == DIRTY;

        match child_presence {
            Absent => {
                panic!("Please use `Present` or `Spent` presence when child flags are specified.");
            }
            Present => {
                let (utxo, _) = create_utxo(0);
                let entry = UtxoEntry::new(utxo, is_fresh, is_dirty);
                single_entry_map.insert(key, entry);
            }
            Spent => {
                let entry = UtxoEntry{
                    status: UtxoStatus::Spent,
                    is_dirty,
                    is_fresh
                };
                single_entry_map.insert(key, entry);
            }
        }
    }

    // perform batch write
    let res = parent.batch_write(single_entry_map, *key.outpoint_hash());
    let entry = parent.utxos.get(&key);

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
    parent_presence: Presence,
    cache_presence: Presence,
    result_presence: Presence,
    cache_flags: Option<u8>,
    result_flags: Option<u8>,
) {
    let mut parent = UtxosCache::default();
    let (parent_utxo, parent_outpoint) =
        insert_single_entry(&mut parent, &parent_presence, Some(FRESH | DIRTY), None);

    let mut child = match parent_presence {
        Absent => UtxosCache::default(),
        _ => UtxosCache::new(&parent),
    };
    let (child_utxo, child_outpoint) = insert_single_entry(
        &mut child,
        &cache_presence,
        cache_flags,
        Some(parent_outpoint),
    );
    let key = OutPointKey::from(&child_outpoint);

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
            let new_height = utxo.height().checked_add(1).expect("should be able to increment");
            utxo.set_height(new_height);
            expected_utxo = Some(utxo.clone());
        }
    }

    let entry = child.utxos.get(&key);
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

#[test]
#[rustfmt::skip]
fn add_utxo_test() {
    /*
                CACHE PRESENCE CACHE Flags      Possible    RESULT flags       RESULT of `add_utxo` method
                                                Overwrite
    */
    check_add_utxo(Absent,    None,               false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(Absent,    None,               true,   Some(DIRTY),         Ok(()));

    check_add_utxo(Spent,     Some(0),            false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(Spent,     Some(0),            true,   Some(DIRTY),         Ok(()));

    check_add_utxo(Spent,     Some(FRESH),        false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(Spent,     Some(FRESH),        true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(Spent,     Some(DIRTY),        false,  Some(DIRTY),         Ok(()));
    check_add_utxo(Spent,     Some(DIRTY),        true,   Some(DIRTY),         Ok(()));

    check_add_utxo(Spent,     Some(FRESH | DIRTY),false,  Some(FRESH | DIRTY), Ok(()));
    check_add_utxo(Spent,     Some(FRESH | DIRTY),true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(Present,   Some(0),            false,  None,                Err(OverwritingUtxo));
    check_add_utxo(Present,   Some(0),            true,   Some(DIRTY),         Ok(()));

    check_add_utxo(Present,   Some(FRESH),        false,  None,                Err(OverwritingUtxo));
    check_add_utxo(Present,   Some(FRESH),        true,   Some(FRESH | DIRTY), Ok(()));

    check_add_utxo(Present,   Some(DIRTY),        false,  None,                Err(OverwritingUtxo));
    check_add_utxo(Present,   Some(DIRTY),        true,   Some(DIRTY),         Ok(()));

    check_add_utxo(Present,   Some(FRESH | DIRTY), false, None,                Err(OverwritingUtxo));
    check_add_utxo(Present,   Some(FRESH | DIRTY), true,  Some(FRESH | DIRTY), Ok(()));
}

#[test]
#[rustfmt::skip]
fn spend_utxo_test() {
    /*
                            PARENT     CACHE
                            PRESENCE   PRESENCE  CACHE Flags          RESULT Flags
    */
    assert!(!check_spend_utxo(Absent, Absent,   None,                None));
    assert!(check_spend_utxo(Absent,  Spent,    Some(0),             Some(DIRTY)));
    assert!(check_spend_utxo(Absent,  Spent,    Some(FRESH),         None));
    assert!(check_spend_utxo(Absent,  Spent,    Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Absent,  Spent,    Some(FRESH | DIRTY), None));
    assert!(check_spend_utxo(Absent,  Present,  Some(0),             Some(DIRTY)));
    assert!(check_spend_utxo(Absent,  Present,  Some(FRESH),         None));
    assert!(check_spend_utxo(Absent,  Present,  Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Absent,  Present,  Some(FRESH | DIRTY), None));

    // this should fail, since there's nothing to remove.
    assert!(!check_spend_utxo(Spent,   Absent,   None,                None));
    assert!(check_spend_utxo(Spent,   Spent,    Some(0),             Some(DIRTY)));

    // this should fail, as there's nothing to remove.
    assert!(!check_spend_utxo(Spent,   Absent,   Some(FRESH),         None));
    assert!(check_spend_utxo(Spent,   Spent,    Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Spent,   Spent,    Some(FRESH | DIRTY), None));
    assert!(check_spend_utxo(Spent,   Present,  Some(0),             Some(DIRTY)));
    assert!(check_spend_utxo(Spent,   Present,  Some(FRESH),         None));
    assert!(check_spend_utxo(Spent,   Present,  Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Spent,   Present,  Some(FRESH | DIRTY), None));
    assert!(check_spend_utxo(Present, Absent,   None,                Some(DIRTY)));
    assert!(check_spend_utxo(Present, Spent,    Some(0),             Some(DIRTY)));
    assert!(check_spend_utxo(Present, Spent,    Some(FRESH),         None));
    assert!(check_spend_utxo(Present, Spent,    Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Present, Spent,    Some(FRESH | DIRTY), None));
    assert!(check_spend_utxo(Present, Present,  Some(0),             Some(DIRTY)));
    assert!(check_spend_utxo(Present, Present,  Some(FRESH),         None));
    assert!(check_spend_utxo(Present, Present,  Some(DIRTY),         Some(DIRTY)));
    assert!(check_spend_utxo(Present, Present,  Some(FRESH | DIRTY), None));
}

#[test]
#[rustfmt::skip]
fn batch_write_test() {
    /*
                    PARENT     CACHE     RESULT
                    PRESENCE   PRESENCE  PRESENCE          PARENT Flags          CACHE Flags          RESULT Flags
    */
    check_write_utxo(Absent, Absent,    Ok(Absent),             None,               None,               None);
    check_write_utxo(Absent, Spent ,    Ok(Spent),              None,               Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Absent, Spent ,    Ok(Absent),             None,               Some(FRESH | DIRTY),None );
    check_write_utxo(Absent, Present,   Ok(Present),            None,               Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Absent, Present,   Ok(Present),            None,               Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_write_utxo(Spent , Absent,    Ok(Spent),              Some(0),            None,               Some(0));
    check_write_utxo(Spent , Absent,    Ok(Spent),              Some(FRESH),        None,               Some(FRESH));
    check_write_utxo(Spent , Absent,    Ok(Spent),              Some(DIRTY),        None,               Some(DIRTY));
    check_write_utxo(Spent , Absent,    Ok(Spent),              Some(FRESH | DIRTY),None,               Some(FRESH | DIRTY));
    check_write_utxo(Spent , Spent ,    Ok(Spent),              Some(0),            Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Spent , Spent ,    Ok(Spent),              Some(0),            Some(FRESH | DIRTY),Some(DIRTY));
    check_write_utxo(Spent , Spent ,    Ok(Absent),             Some(FRESH),        Some(DIRTY),        None);
    check_write_utxo(Spent , Spent ,    Ok(Absent),             Some(FRESH),        Some(FRESH | DIRTY),None);
    check_write_utxo(Spent , Spent ,    Ok(Spent),              Some(DIRTY),        Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Spent , Spent ,    Ok(Spent),              Some(DIRTY),        Some(FRESH | DIRTY),Some(DIRTY));
    check_write_utxo(Spent , Spent ,    Ok(Absent),             Some(FRESH | DIRTY),Some(DIRTY),        None);
    check_write_utxo(Spent , Spent ,    Ok(Absent),             Some(FRESH | DIRTY),Some(FRESH | DIRTY),None);
    check_write_utxo(Spent , Present,   Ok(Present),            Some(0),            Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(0),            Some(FRESH | DIRTY),Some(DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(FRESH),        Some(DIRTY),        Some(FRESH | DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(FRESH),        Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(DIRTY),        Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(DIRTY),        Some(FRESH | DIRTY),Some(DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(FRESH | DIRTY),Some(DIRTY),        Some(FRESH | DIRTY));
    check_write_utxo(Spent , Present,   Ok(Present),            Some(FRESH | DIRTY),Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_write_utxo(Present, Absent,   Ok(Present),            Some(0),            None,               Some(0));
    check_write_utxo(Present, Absent,   Ok(Present),            Some(FRESH),        None,               Some(FRESH));
    check_write_utxo(Present, Absent,   Ok(Present),            Some(DIRTY),        None,               Some(DIRTY));
    check_write_utxo(Present, Absent,   Ok(Present),            Some(FRESH | DIRTY),None ,              Some(FRESH | DIRTY));
    check_write_utxo(Present, Spent ,   Ok(Spent),              Some(0),            Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Present, Spent ,   Err(UtxoAlreadyExists), Some(0),            Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Spent ,   Ok(Absent),             Some(FRESH),        Some(DIRTY),        None);
    check_write_utxo(Present, Spent ,   Err(UtxoAlreadyExists), Some(FRESH),        Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Spent ,   Ok(Spent),              Some(DIRTY),        Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Present, Spent ,   Err(UtxoAlreadyExists), Some(DIRTY),        Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Spent ,   Ok(Absent),             Some(FRESH | DIRTY),Some(DIRTY),        None);
    check_write_utxo(Present, Spent ,   Err(UtxoAlreadyExists), Some(FRESH | DIRTY),Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Present,  Ok(Present),            Some(0),            Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Present, Present,  Err(UtxoAlreadyExists), Some(0),            Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Present,  Ok(Present),            Some(FRESH),        Some(DIRTY),        Some(FRESH | DIRTY));
    check_write_utxo(Present, Present,  Err(UtxoAlreadyExists), Some(FRESH),        Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Present,  Ok(Present),            Some(DIRTY),        Some(DIRTY),        Some(DIRTY));
    check_write_utxo(Present, Present,  Err(UtxoAlreadyExists), Some(DIRTY),        Some(FRESH | DIRTY),None);
    check_write_utxo(Present, Present,  Ok(Present),            Some(FRESH | DIRTY),Some(DIRTY),        Some(FRESH | DIRTY));
    check_write_utxo(Present, Present,  Err(UtxoAlreadyExists), Some(FRESH | DIRTY),Some(FRESH | DIRTY),None);
}

#[test]
#[rustfmt::skip]
fn access_utxo_test() {
    /*
                    PARENT     CACHE     RESULT     CACHE
                    PRESENCE   PRESENCE  PRESENCE   Flags        RESULT Flags
    */
    check_get_mut_utxo(Absent, Absent, Absent,   None,               None);
    check_get_mut_utxo(Absent, Spent , Spent ,   Some(0),            Some(0));
    check_get_mut_utxo(Absent, Spent , Spent ,   Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(Absent, Spent , Spent ,   Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(Absent, Spent , Spent ,   Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(Absent, Present, Present, Some(0),            Some(0));
    check_get_mut_utxo(Absent, Present, Present, Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(Absent, Present, Present, Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(Absent, Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(Spent , Absent, Absent,   None,               None);
    check_get_mut_utxo(Spent , Spent , Spent ,   Some(0),            Some(0));
    check_get_mut_utxo(Spent , Spent , Spent ,   Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(Spent , Spent , Spent ,   Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(Spent , Spent , Spent ,   Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(Spent , Present, Present, Some(0),            Some(0));
    check_get_mut_utxo(Spent , Present, Present, Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(Spent , Present, Present, Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(Spent , Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(Present, Absent, Present, None,               Some(0));
    check_get_mut_utxo(Present, Spent , Spent ,  Some(0),            Some(0));
    check_get_mut_utxo(Present, Spent , Spent ,  Some(FRESH),        Some(FRESH));
    check_get_mut_utxo(Present, Spent , Spent ,  Some(DIRTY),        Some(DIRTY));
    check_get_mut_utxo(Present, Spent , Spent ,  Some(FRESH | DIRTY),Some(FRESH | DIRTY));
    check_get_mut_utxo(Present, Present, Present, Some(0),           Some(0));
    check_get_mut_utxo(Present, Present, Present, Some(FRESH),       Some(FRESH));
    check_get_mut_utxo(Present, Present, Present, Some(DIRTY),       Some(DIRTY));
    check_get_mut_utxo(Present, Present, Present, Some(FRESH | DIRTY),Some(FRESH | DIRTY));
}

#[test]
fn derive_cache_test() {
    let mut cache = UtxosCache::default();

    let (utxo, outpoint_1) = create_utxo(10);
    assert!(cache.add_utxo(utxo, &outpoint_1, false).is_ok());

    let (utxo, outpoint_2) = create_utxo(20);
    assert!(cache.add_utxo(utxo, &outpoint_2, false).is_ok());

    let mut extra_cache = cache.derive_cache();
    assert!(extra_cache.utxos.is_empty());

    assert!(extra_cache.has_utxo(&outpoint_1));
    assert!(extra_cache.has_utxo(&outpoint_2));

    let (utxo, outpoint) = create_utxo(30);
    assert!(extra_cache.add_utxo(utxo, &outpoint, true).is_ok());

    assert!(!cache.has_utxo(&outpoint));
}
