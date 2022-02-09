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
        0xa87e4adcb5a356a3247b699d2c36cf217a135b43a29c3883f46eaed72abbd128
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    expect![[r#"
        0x228fea54993e15647ec580ccabde223444b43bd52c82579a2d99ffcfb756c662
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xf94788524c18ef1fc4b402398f7dc75a42bc6cba31465c14d3fcc1c25bd71a2e
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xdfe2df919b4eab0ee3d10fff2f1f964f33c6a50c9b2e3a18fd9297088b64576e
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0xd6361975b7013da6a67a449bfd2d5beddcd02ed86aabfa04fd25f8a15443f7ad
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0xab0e6bfe8878d893f153ba10846fb965373f6aa09c998ab8b61260e2c23affd5
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
