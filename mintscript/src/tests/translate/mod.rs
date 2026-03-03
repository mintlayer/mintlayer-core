// Copyright (c) 2024 RBB S.r.l
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

use std::collections::BTreeMap;

use strum::IntoEnumIterator as _;

use ::utils::concatln;
use common::{
    chain::{
        block::BlockRewardTransactable,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        signature::inputsig::authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
        stakelock::StakePoolData,
        tokens, AccountNonce, AccountSpending, OrderAccountCommand, OrderData, OrderId,
    },
    primitives::per_thousand::PerThousand,
};
use crypto::vrf::{VRFPrivateKey, VRFPublicKey};
use logging::log;
use pos_accounting::{DelegationData, PoolData};
use serialization::Encode;
use tokens_accounting::TokenData;

use super::*;

use self::mocks::MockSigInfoProvider;

mod mocks;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

// Like input info but owned
enum TestInputInfo {
    Utxo {
        outpoint: UtxoOutPoint,
        utxo: utxo::Utxo,
    },
    Account {
        outpoint: AccountOutPoint,
    },
    AccountCommand {
        command: AccountCommand,
    },
    OrderAccountCommand {
        command: OrderAccountCommand,
    },
}

impl TestInputInfo {
    const fn utxo(outpoint: UtxoOutPoint, utxo: utxo::Utxo) -> Self {
        Self::Utxo { outpoint, utxo }
    }

    fn to_input_info(&self) -> InputInfo<'_> {
        match self {
            Self::Utxo { outpoint, utxo } => InputInfo::Utxo {
                outpoint,
                utxo: utxo.output().clone(),
                utxo_source: Some(utxo.source().clone()),
            },
            Self::Account { outpoint } => InputInfo::Account { outpoint },
            Self::AccountCommand { command } => InputInfo::AccountCommand { command },
            Self::OrderAccountCommand { command } => InputInfo::OrderAccountCommand { command },
        }
    }
}

// Just set up some sample data

fn coins(amount: u128) -> OutputValue {
    OutputValue::Coin(Amount::from_atoms(amount))
}

// Create a keypair. We need constant data so generate it deterministically from given seed.
fn keypair(seed: u64) -> (PrivateKey, PublicKey) {
    PrivateKey::new_from_rng(&mut TestRng::new(Seed(seed)), KeyKind::Secp256k1Schnorr)
}

// Create a fake ID by broadcasting a single byte everywhere
fn fake_id<T>(byte: u8) -> Id<T> {
    Id::new(H256([byte; 32]))
}

fn vrf_keypair(seed: u64) -> (VRFPrivateKey, VRFPublicKey) {
    let kind = crypto::vrf::VRFKeyKind::Schnorrkel;
    VRFPrivateKey::new_from_rng(&mut TestRng::new(Seed(seed)), kind)
}

fn dest_pk(pk_seed: u64) -> Destination {
    Destination::PublicKey(keypair(pk_seed).1)
}

fn dest_ms(pk_seed: u64) -> Destination {
    Destination::ClassicMultisig((&keypair(pk_seed).1).into())
}

fn outpoint_tx(tx_id_byte: u8, index: u32) -> UtxoOutPoint {
    UtxoOutPoint::new(fake_id::<Transaction>(tx_id_byte).into(), index)
}

fn block_source(height: u64) -> UtxoSource {
    UtxoSource::Blockchain(BlockHeight::new(height))
}

// Turn output into UTXO type info, with other fields set to some defaults
fn tii(output: TxOutput) -> TestInputInfo {
    TestInputInfo::utxo(outpoint_tx(0x01, 5), Utxo::new(output, block_source(500)))
}

fn transfer_pk(pk_seed: u64, amt: u128) -> TestInputInfo {
    tii(TxOutput::Transfer(coins(amt), dest_pk(pk_seed)))
}

fn transfer_pk_tl(pk_seed: u64, amt: u128, timelock: OutputTimeLock) -> TestInputInfo {
    let amt = coins(amt);
    tii(TxOutput::LockThenTransfer(amt, dest_pk(pk_seed), timelock))
}

fn transfer_pkh(pkh_byte: u8, amt: u128) -> TestInputInfo {
    let pkh = common::address::pubkeyhash::PublicKeyHash::from_slice(&[pkh_byte; 20]);
    let dest = Destination::PublicKeyHash(pkh);
    tii(TxOutput::Transfer(coins(amt), dest))
}

fn create_pool(staker_seed: u64, decom_seed: u64) -> TestInputInfo {
    let data = StakePoolData::new(
        Amount::from_atoms(5677777),
        dest_pk(staker_seed),
        vrf_keypair(15).1,
        dest_pk(decom_seed),
        PerThousand::new(10).unwrap(),
        Amount::from_atoms(321_000),
    );
    let id = fake_id(0xff);
    tii(TxOutput::CreateStakePool(id, Box::new(data)))
}

fn burn(amount: u128) -> TestInputInfo {
    tii(TxOutput::Burn(coins(amount)))
}

fn prod_block(dest: Destination, pool_id: PoolId) -> TestInputInfo {
    tii(TxOutput::ProduceBlockFromStake(dest, pool_id))
}

fn delegate(amount: u128, del_id_byte: u8) -> TestInputInfo {
    let del_id = fake_id(del_id_byte);
    tii(TxOutput::DelegateStaking(
        Amount::from_atoms(amount),
        del_id,
    ))
}

fn htlc(spend_seed: u64, refund_seed: u64, timelock: OutputTimeLock) -> TestInputInfo {
    let amt = coins(1333);
    let htlc = HashedTimelockContract {
        secret_hash: HtlcSecretHash::from_low_u64_be(13),
        spend_key: dest_pk(spend_seed),
        refund_timelock: timelock,
        refund_key: dest_ms(refund_seed),
    };
    tii(TxOutput::Htlc(amt, Box::new(htlc)))
}

fn nosig() -> InputWitness {
    InputWitness::NoSignature(None)
}

fn stdsig(byte: u8) -> InputWitness {
    let sht = SigHashType::default();
    InputWitness::Standard(StandardInputSignature::new(sht, vec![byte; 2]))
}

fn htlc_spend_sig(byte: u8) -> InputWitness {
    let sht = SigHashType::default();
    let raw_sig = vec![byte; 2];
    let secret = HtlcSecret::new([6; 32]);
    let sig_with_secret = AuthorizedHashedTimelockContractSpend::Spend(secret, raw_sig);
    let serialized_sig = sig_with_secret.encode();

    InputWitness::Standard(StandardInputSignature::new(sht, serialized_sig))
}

fn htlc_refund_sig(byte: u8) -> InputWitness {
    let sht = SigHashType::default();
    let raw_sig = vec![byte; 2];
    let sig_with_secret = AuthorizedHashedTimelockContractSpend::Refund(raw_sig);
    let serialized_sig = sig_with_secret.encode();

    InputWitness::Standard(StandardInputSignature::new(sht, serialized_sig))
}

fn deleg0() -> (DelegationId, DelegationData) {
    let data = DelegationData::new(fake_id(0x57), dest_pk(101));
    (fake_id(0x75), data)
}

fn pool0_decom() -> Destination {
    dest_pk(0x1337)
}

fn pool0() -> (PoolId, PoolData) {
    let data = PoolData::new(
        pool0_decom(),
        Amount::from_atoms(500_000_000),
        Amount::from_atoms(2_000),
        vrf_keypair(2337).1,
        PerThousand::new(2).unwrap(),
        Amount::from_atoms(1_000),
    );
    (fake_id(0xbc), data)
}

fn order0() -> (OrderId, OrderData) {
    let data = OrderData::new(
        dest_pk(0x33),
        OutputValue::Coin(Amount::from_atoms(100)),
        OutputValue::Coin(Amount::from_atoms(200)),
    );
    (fake_id(0x44), data)
}

fn create_order(data: OrderData) -> TestInputInfo {
    tii(TxOutput::CreateOrder(Box::new(data)))
}

fn account_spend(deleg: DelegationId, amount: u128) -> TestInputInfo {
    let spend = AccountSpending::DelegationBalance(deleg, Amount::from_atoms(amount));
    let outpoint = AccountOutPoint::new(AccountNonce::new(7), spend);
    TestInputInfo::Account { outpoint }
}

fn token0() -> (TokenId, TokenData) {
    let data = tokens_accounting::FungibleTokenData::new_unchecked(
        Vec::from(r"MEH"),
        3,
        Vec::from(r"https://acme.wtf/the_meh_token"),
        tokens::TokenTotalSupply::Lockable,
        false,
        tokens::IsTokenFrozen::No(tokens::IsTokenFreezable::Yes),
        dest_pk(0x33f),
    );
    let data = TokenData::FungibleToken(data);
    (fake_id(0xa3), data)
}

fn mint(id: TokenId, amount: u128) -> TestInputInfo {
    let command = AccountCommand::MintTokens(id, Amount::from_atoms(amount));
    TestInputInfo::AccountCommand { command }
}

fn conclude_order_v0(id: OrderId) -> TestInputInfo {
    let command = AccountCommand::ConcludeOrder(id);
    TestInputInfo::AccountCommand { command }
}

fn fill_order_v0(id: OrderId) -> TestInputInfo {
    let command = AccountCommand::FillOrder(id, Amount::from_atoms(1), dest_pk(0x4));
    TestInputInfo::AccountCommand { command }
}

fn conclude_order_v1(id: OrderId) -> TestInputInfo {
    let command = OrderAccountCommand::ConcludeOrder(id);
    TestInputInfo::OrderAccountCommand { command }
}

fn fill_order_v1(id: OrderId) -> TestInputInfo {
    let command = OrderAccountCommand::FillOrder(id, Amount::from_atoms(1));
    TestInputInfo::OrderAccountCommand { command }
}

fn freeze_order(id: OrderId) -> TestInputInfo {
    let command = OrderAccountCommand::FreezeOrder(id);
    TestInputInfo::OrderAccountCommand { command }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, strum::EnumIter, derive_more::Display,
)]
enum Mode {
    Reward,
    TxSigOnly,
    TxTimelockOnly,
    TxFull,
}

// The test itself
// TODO: it's better to refactor this test further and:
// * split the single test into multiple ones;
// * compare the original Rust objects instead of their string representations.

#[rstest::rstest]
#[case(burn(100_000), nosig(), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
#[case(burn(200_000), stdsig(0x51), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
#[case(transfer_pk(12, 555), nosig(), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x020003e843fa18427b5e71eb6b94eaffcbf52ddc8dc6e843d259f31d7d5566ddc1b6c2, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020003e843fa18427b5e71eb6b94eaffcbf52ddc8dc6e843d259f31d7d5566ddc1b6c2, 0x0000)"),
])]
#[case(transfer_pk(13, 557), stdsig(0x51), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085151)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085151)"),
])]
#[case(transfer_pkh(0x12, 300_000), stdsig(0x52), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x011212121212121212121212121212121212121212, 0x0101085252)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x011212121212121212121212121212121212121212, 0x0101085252)"),
])]
#[case(transfer_pkh(0x12, 300_000), nosig(), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x011212121212121212121212121212121212121212, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x011212121212121212121212121212121212121212, 0x0000)"),
])]
#[case(
    transfer_pk_tl(12, 555, tl_for_blocks(600)),
    stdsig(0x5d),
    &[
        (Mode::Reward, "ERROR: Illegal output spend"),
        (Mode::TxSigOnly, "signature(0x020003e843fa18427b5e71eb6b94eaffcbf52ddc8dc6e843d259f31d7d5566ddc1b6c2, 0x0101085d5d)"),
        (Mode::TxTimelockOnly, "after_blocks(600)"),
        (Mode::TxFull, concatln!(
            "threshold(2, [",
            "    after_blocks(600),",
            "    signature(0x020003e843fa18427b5e71eb6b94eaffcbf52ddc8dc6e843d259f31d7d5566ddc1b6c2, 0x0101085d5d),",
            "])"
        )),
    ]
)]
#[case(
    transfer_pk_tl(13, 557, tl_until_height(155_554)),
    stdsig(0x59),
    &[
        (Mode::Reward, "ERROR: Illegal output spend"),
        (Mode::TxSigOnly, "signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085959)"),
        (Mode::TxTimelockOnly, "until_height(155554)"),
        (Mode::TxFull, concatln!(
            "threshold(2, [",
            "    until_height(155554),",
            "    signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085959),",
            "])"
        )),
    ]
)]
#[case(
    transfer_pk_tl(14, 558, tl_for_secs(365 * 24 * 60 * 60)),
    stdsig(0x5a),
    &[
        (Mode::Reward, "ERROR: Illegal output spend"),
        (Mode::TxSigOnly, "signature(0x02000253f0022f209dfa5c224294e4aaf337dc062ec9f689fcc04b4f2196a71fad3758, 0x0101085a5a)"),
        (Mode::TxTimelockOnly, "after_seconds(31536000)"),
        (Mode::TxFull, concatln!(
            "threshold(2, [",
            "    after_seconds(31536000),",
            "    signature(0x02000253f0022f209dfa5c224294e4aaf337dc062ec9f689fcc04b4f2196a71fad3758, 0x0101085a5a),",
            "])"
        )),
    ]
)]
#[case(
    transfer_pk_tl(15, 559, tl_until_time(1_718_120_714)),
    stdsig(0x5b),
    &[
        (Mode::Reward, "ERROR: Illegal output spend"),
        (Mode::TxSigOnly, "signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085b5b)"),
        (Mode::TxTimelockOnly, "until_time(1718120714)"),
        (Mode::TxFull, concatln!(
            "threshold(2, [",
            "    until_time(1718120714),",
            "    signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085b5b),",
            "])"
        )),
    ]
)]
#[case(
    transfer_pk_tl(16, 560, tl_until_height(999_999)),
    nosig(),
    &[
        (Mode::Reward, "ERROR: Illegal output spend"),
        (Mode::TxSigOnly, "signature(0x020002ebcadc73233ea7fc2c8e2e5bcafc7dd4b46444a60d9b5bc9a965d2c6d8a44ebb, 0x0000)"),
        (Mode::TxTimelockOnly, "until_height(999999)"),
        (Mode::TxFull, concatln!(
            "threshold(2, [",
            "    until_height(999999),",
            "    signature(0x020002ebcadc73233ea7fc2c8e2e5bcafc7dd4b46444a60d9b5bc9a965d2c6d8a44ebb, 0x0000),",
            "])"
        )),
    ]
)]
#[case(
    prod_block(dest_pk(0x543), fake_id(0xe0)),
    stdsig(0x60),
    &[
        (Mode::Reward, "signature(0x0200032318d5bcf9bd716cad704d6052b9ea8419b7f691be78be7e76d393a4ed86448a, 0x0101086060)"),
        (Mode::TxSigOnly, "ERROR: Stake pool e0e0…e0e0 does not exist"),
        (Mode::TxTimelockOnly, "true"),
        (Mode::TxFull, "ERROR: Stake pool e0e0…e0e0 does not exist"),
    ]
)]
#[case(prod_block(dest_pk(0x544), fake_id(0xe1)), nosig(), &[
    (Mode::Reward, "signature(0x0200034696310c540f0a749bc023003c3c698dcc61bbb75a4b37f429f250eb8b7554b1, 0x0000)"),
    (Mode::TxSigOnly, "ERROR: Stake pool e1e1…e1e1 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Stake pool e1e1…e1e1 does not exist"),
])]
#[case(prod_block(pool0_decom(), fake_id(0xe2)), stdsig(0x63), &[
    (Mode::Reward, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086363)"),
    (Mode::TxSigOnly, "ERROR: Stake pool e2e2…e2e2 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Stake pool e2e2…e2e2 does not exist"),
])]
#[case(prod_block(dest_pk(0x545), pool0().0), stdsig(0x64), &[
    (Mode::Reward, "signature(0x020002e7759586e15d0e2b961f097a714515c4e145f4963f24ce99063f3ec9d0211e7a, 0x0101086464)"),
    (Mode::TxSigOnly, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086464)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086464)"),
])]
#[case(prod_block(pool0_decom(), pool0().0), stdsig(0x65), &[
    (Mode::Reward, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086565)"),
    (Mode::TxSigOnly, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086565)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x0200024efcfcb197750301c44ffc5a8b176159a2c5de0b9945c5998245054efea6ac89, 0x0101086565)"),
])]
#[case(delegate(5_000_000, 0xe2), stdsig(0x61), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
#[case(delegate(6_000_000, 0xe3), nosig(), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
#[case(create_pool(14, 15), stdsig(0x53), &[
    (Mode::Reward, "signature(0x02000253f0022f209dfa5c224294e4aaf337dc062ec9f689fcc04b4f2196a71fad3758, 0x0101085353)"),
    (Mode::TxSigOnly, "signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085353)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085353)"),
])]
#[case(account_spend(deleg0().0, 579), stdsig(0x54), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x020002819f7f36a2790938e5f45ac07053110b8e985fbf7cff8a60a403e95b2a2c24fc, 0x0101085454)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020002819f7f36a2790938e5f45ac07053110b8e985fbf7cff8a60a403e95b2a2c24fc, 0x0101085454)"),
])]
#[case(account_spend(fake_id(0xf5), 580), stdsig(0x55), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "ERROR: Delegation f5f5…f5f5 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Delegation f5f5…f5f5 does not exist"),
])]
#[case(account_spend(deleg0().0, 581), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x020002819f7f36a2790938e5f45ac07053110b8e985fbf7cff8a60a403e95b2a2c24fc, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020002819f7f36a2790938e5f45ac07053110b8e985fbf7cff8a60a403e95b2a2c24fc, 0x0000)"),
])]
#[case(mint(fake_id(0xa1), 581), stdsig(0x56), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "ERROR: Token with id a1a1…a1a1 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Token with id a1a1…a1a1 does not exist"),
])]
#[case(mint(token0().0, 582), stdsig(0x57), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x020003745607a08b12634e402eec525ddaaaaab73cc3951cd232cb88ad934f4be717f6, 0x0101085757)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020003745607a08b12634e402eec525ddaaaaab73cc3951cd232cb88ad934f4be717f6, 0x0101085757)"),
])]
#[case(mint(token0().0, 582), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x020003745607a08b12634e402eec525ddaaaaab73cc3951cd232cb88ad934f4be717f6, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x020003745607a08b12634e402eec525ddaaaaab73cc3951cd232cb88ad934f4be717f6, 0x0000)"),
])]
#[case(htlc(11, 12, tl_until_height(999_999)), htlc_spend_sig(0x54), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x020003574c6b846c9a4c555ea75d771d5a40564b9ef37419682da12573e1d8ac27d71e, 0x0101085454)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, concatln!(
        "threshold(2, [",
        "    Hash160(0x50000000000000000000000000000000000000000d, 0x0606060606060606060606060606060606060606060606060606060606060606),",
        "    signature(0x020003574c6b846c9a4c555ea75d771d5a40564b9ef37419682da12573e1d8ac27d71e, 0x0101085454),",
        "])"
    )),
])]
#[case(htlc(13, 14, tl_for_secs(1111)), htlc_spend_sig(0x58), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085858)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, concatln!(
        "threshold(2, [",
        "    Hash160(0x50000000000000000000000000000000000000000d, 0x0606060606060606060606060606060606060606060606060606060606060606),",
        "    signature(0x020002a3fe239606e407ea161143e42c7c3ef0059573466950a910b28289df247df7a3, 0x0101085858),",
        "])"
    )),
])]
#[case(htlc(15, 16, tl_until_time(99)), htlc_spend_sig(0x53), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085353)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, concatln!(
        "threshold(2, [",
        "    Hash160(0x50000000000000000000000000000000000000000d, 0x0606060606060606060606060606060606060606060606060606060606060606),",
        "    signature(0x0200039315c9da756f584d5a7fff618d230bf13115a43d63e7c7d464bb513ab6be7bbc, 0x0101085353),",
        "])"
    )),
])]
#[case(htlc(17, 18, tl_for_secs(124)), htlc_refund_sig(0x54), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x041c9bb73a209c49363022813e7197ac80c761d80b, 0x0101085454)"),
    (Mode::TxTimelockOnly, "after_seconds(124)"),
    (Mode::TxFull, concatln!(
        "threshold(2, [",
        "    after_seconds(124),",
        "    signature(0x041c9bb73a209c49363022813e7197ac80c761d80b, 0x0101085454),",
        "])"
    )),
])]
#[case(htlc(19, 20, tl_for_blocks(1000)), htlc_refund_sig(0x55), &[
    (Mode::Reward, "ERROR: Illegal output spend"),
    (Mode::TxSigOnly, "signature(0x04d55789fd7dd4b58f8bdb889a0d31cac70e67df92, 0x0101085555)"),
    (Mode::TxTimelockOnly, "after_blocks(1000)"),
    (Mode::TxFull, concatln!(
        "threshold(2, [",
        "    after_blocks(1000),",
        "    signature(0x04d55789fd7dd4b58f8bdb889a0d31cac70e67df92, 0x0101085555),",
        "])"
    )),
])]
#[case(create_order(order0().1), nosig(), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
#[case(create_order(order0().1), stdsig(0x57), &[
    (Mode::Reward, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxSigOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxTimelockOnly, "ERROR: Attempt to spend an unspendable output"),
    (Mode::TxFull, "ERROR: Attempt to spend an unspendable output"),
])]
// Conclude order v0
#[case(conclude_order_v0(order0().0), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
])]
#[case(conclude_order_v0(fake_id(0x88)), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "ERROR: Order with id 8888…8888 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Order with id 8888…8888 does not exist"),
])]
#[case(conclude_order_v0(order0().0), stdsig(0x44), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
])]
#[case(conclude_order_v0(order0().0), stdsig(0x45), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
])]
// Conclude order v1
#[case(conclude_order_v1(order0().0), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
])]
#[case(conclude_order_v1(fake_id(0x88)), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "ERROR: Order with id 8888…8888 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Order with id 8888…8888 does not exist"),
])]
#[case(conclude_order_v1(order0().0), stdsig(0x44), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
])]
#[case(conclude_order_v1(order0().0), stdsig(0x45), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
])]
// Fill order v0
#[case(fill_order_v0(order0().0), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "true"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "true"),
])]
#[case(fill_order_v0(fake_id(0x77)), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "true"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "true"),
])]
#[case(fill_order_v0(order0().0), stdsig(0x45), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "true"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "true"),
])]
// Fill order v1
#[case(fill_order_v1(order0().0), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x00, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x00, 0x0000)"),
])]
#[case(fill_order_v1(fake_id(0x77)), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x00, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x00, 0x0000)"),
])]
#[case(fill_order_v1(order0().0), stdsig(0x45), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x00, 0x0101084545)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x00, 0x0101084545)"),
])]
// Freeze order
#[case(freeze_order(order0().0), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0000)"),
])]
#[case(freeze_order(fake_id(0x88)), nosig(), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "ERROR: Order with id 8888…8888 does not exist"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "ERROR: Order with id 8888…8888 does not exist"),
])]
#[case(freeze_order(order0().0), stdsig(0x44), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084444)"),
])]
#[case(freeze_order(order0().0), stdsig(0x45), &[
    (Mode::Reward, "ERROR: Illegal account spend"),
    (Mode::TxSigOnly, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
    (Mode::TxTimelockOnly, "true"),
    (Mode::TxFull, "signature(0x02000236d8c927b785e27385737e82cdde2e06dc510ab8545d6eab0ca05c36040a437c, 0x0101084545)"),
])]
fn translate(
    #[case] test_input_info: TestInputInfo,
    #[case] witness: InputWitness,
    #[case] expected_results: &[(Mode, &str)],
) {
    let input_info = test_input_info.to_input_info();
    let tokens = [token0()];
    let delegs = [deleg0()];
    let pools = [pool0()];
    let orders = [order0()];
    let sig_info = MockSigInfoProvider::new(input_info, witness, tokens, pools, delegs, orders);
    let expected_results = expected_results.iter().copied().collect::<BTreeMap<_, _>>();

    for mode in Mode::iter() {
        log::debug!("Checking mode {mode}");

        let result = match mode {
            Mode::Reward => BlockRewardTransactable::<'_>::translate_input(&sig_info),
            Mode::TxFull => SignedTransaction::translate_input(&sig_info),
            Mode::TxTimelockOnly => TimelockOnly::translate_input(&sig_info),
            Mode::TxSigOnly => SignatureOnlyTx::translate_input(&sig_info),
        };

        let expected_result = *expected_results.get(&mode).unwrap();

        let result_str = match result {
            Ok(script) => format!("{script}"),
            Err(err) => format!("ERROR: {err}"),
        };

        assert_eq!(result_str, expected_result);
    }
}
