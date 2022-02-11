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
        [TxInput::new(OutpointSource::Transaction(Id::new(&hash0)), 5, vec![])].to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(
            OutpointSource::Transaction(Id::new(&hash1)),
            3,
            vec![0x01, 0x05, 0x09],
        ),
        TxInput::new(
            OutpointSource::Transaction(Id::new(&hash2)),
            0,
            vec![0x91, 0x55, 0x19, 0x00],
        ),
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
        0xafeecf94474aeac499b40f453762fe9fff9667b277eadaea03e66d89338921fa
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xed50231c2c10fee8b0f273471be0db24913696b83a4400068859f6befe203c78
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0xe8c2995509921f0355bd6be90edc4fb392a2a501a11cb107ecb3cdf87e2145ca
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0x2408a863a0ed230c12bc02e1b84ba6c3f59afa6a84fd977295e757bbf28a02b2
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
