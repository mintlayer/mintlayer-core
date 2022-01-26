use common::chain::transaction::*;
use common::primitives::{Id, Idable, H256};
use expect_test::expect;

#[test]
fn transaction_id_snapshots() {
    let hash0 = H256([0x50; 32]);
    let hash1 = H256([0x51; 32]);
    let hash2 = H256([0x52; 32]);

    let outs0: Vec<TxOutput> =
        [TxOutput::new(25.into(), Destination::ScriptHash(Id::new(&hash0)))].to_vec();
    let ins0: Vec<TxInput> = [TxInput::new(Id::new(&hash0), 5, vec![])].to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(Id::new(&hash1), 3, vec![0x01, 0x05, 0x09]),
        TxInput::new(Id::new(&hash2), 0, vec![0x91, 0x55, 0x19, 0x00]),
    ]
    .to_vec();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    expect![[r#"
        0x72e3990d1647e0e1d8c06d5dc2c63cf6c6172514db611a653850e4d4288e9f65
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    expect![[r#"
        0xf8ea4871f85b120fc3f81179916dc045b5a32e8c7214a0b8f8f96c3862197683
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0x339892c4cc5eee94cd704de9b58a700831e2648235d08ac247859b5ae307d6c4
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0x28c5dcabc7f365d77cf8f48ab7926a9b2176d00f57c4b241141992b968eeebb1
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0x65912e9f07f1161a9436306dd2d4c204903283e51ce4647833f362e614163b2f
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0xe22619f093a0b924f73817529fe36b9d1724bc28b7684a91ecc130850c160a2f
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
