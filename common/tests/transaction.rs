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
        0x2e1ad75bc2c1fcd3145c4631ba6cbc425ac77d8f3902b4c41fef184c528847f9
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0x6e57648b089792fd183a2e9b0ca5c6334f961f2fff0fd1e30eab4e9b91dfe2df
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0xadf74354a1f825fd04faab6ad82ed0dced5b2dfd9b447aa6a63d01b7751936d6
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0xd5ff3ac2e26012b6b88a999ca06a3f3765b96f8410ba53f193d87888fe6b0eab
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
