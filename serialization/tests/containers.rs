mod utils;

use rand::Rng;
use serialization::{Decode, Encode};
use utils::SimpleWrapper;
use std::collections::BTreeMap;

#[test]
fn test_scale_vectors() {
    let vector = vec![-11, 12, -13, 14, -15, 16, -17, 18, -19];
    let enc = SimpleWrapper::encode(&SimpleWrapper(vector.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(vector)));
    let vector = vec![b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k'];
    let enc = SimpleWrapper::encode(&SimpleWrapper(vector.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(vector)));
    let vector = vec![
        "Often".to_string(),
        "the less there is to justify a traditional custom".to_string(),
        "the harder it is to get rid of it.".to_string(),
        "Mark Twain".to_string(),
        "The Adventure of Tom Sawyer".to_string(),
        "Ch 5".to_string(),
    ];
    let enc = SimpleWrapper::encode(&SimpleWrapper(vector.clone()));
    assert!(!enc.is_empty());

    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(vector)));
    let mut vector = Vec::new();
    for _ in 0..1024 {
        vector.push((
            -11i8,
            12u8,
            -13i16,
            14u16,
            -15i32,
            16u32,
            -17i64,
            18u64,
            -19i128,
            20u128,
            "Hello, world!".to_string(),
            Some([0xFF; 32]),
        ));
        vector.push(
            (
                -1i8,
                2u8,
                -1234i16,
                5678u16,
                -1036572536i32,
                2415369116u32,
                -2321372031054735191i64,
                1091632910434195781u64,
                -170141123460424235652481386091358552721i128,
                210614612912676532892982561042679146832u128,
                ("The minister gave out his text and droned along monotonously through an argument that \
            was so prosy that many a head by and by began to nod — and yet it was an argument that \
            dealt in limitless fire and brimstone and thinned the predestined elect down to a company \
            so small as to be hardly worth the saving. Mark Twain, The Adventure of Tom Sawyer, Ch 5").to_string(),
                Some([0x1f; 32]),
            )
        );
    }
    let enc = SimpleWrapper::encode(&SimpleWrapper(vector.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(vector)));
}

#[test]
fn test_scale_btree_map() {
    let mut rng = rand::thread_rng();
    let mut btree_map = BTreeMap::new();
    for _ in 0..1024 {
        btree_map.insert(
            format!("Office Space {}", rng.gen::<u64>()),
            "Deals with real issues in the workplace.".to_string(),
        );
        btree_map.insert(
            format!("Pulp Fiction {}", rng.gen::<u64>()),
            "Masterpiece.".to_string(),
        );
        btree_map.insert(
            format!("The Godfather {}", rng.gen::<u64>()),
            "Very enjoyable.".to_string(),
        );
        btree_map.insert(
            format!("The Blues Brothers {}", rng.gen::<u64>()),
            "Eye lyked it a lot.".to_string(),
        );
    }
    let enc = SimpleWrapper::encode(&SimpleWrapper(btree_map.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(btree_map)));
}
