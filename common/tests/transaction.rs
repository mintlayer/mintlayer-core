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
    let ins0: Vec<TxInput> =
        [TxInput::new(Id::<Transaction>::new(&hash0).into(), 5, vec![])].to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(
            Id::<Transaction>::new(&hash1).into(),
            3,
            vec![0x01, 0x05, 0x09],
        ),
        TxInput::new(
            Id::<Transaction>::new(&hash2).into(),
            0,
            vec![0x91, 0x55, 0x19, 0x00],
        ),
    ]
    .to_vec();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    expect![[r#"
        0x28d1bb2ad7ae6ef483389ca2435b137a21cf362c9d697b24a356a3b5dc4a7ea8
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    expect![[r#"
        0x62c656b7cfff992d9a57822cd53bb4443422deabcc80c57e64153e9954ea8f22
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xfc685449a89c79298273e765eceaa0f81f6b3863b70429820a07626b9d271852
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xb54806907fa4d0763489320a6fd9f3836c560f06313a41318c32d321973ad944
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0xfe3cc928587d0603eef4ea6319076fe8e69324908a443344d3313b53fe2f592b
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0x70cc32e22a7cf73636f1b46f0270f3a9a7e9045e056814e9249ddd0f226aaf0b
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
