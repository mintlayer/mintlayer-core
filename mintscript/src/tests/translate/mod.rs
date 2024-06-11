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

use self::mocks::MockSigInfoProvider;

use super::*;
use common::{
    chain::{
        block::BlockRewardTransactable, stakelock::StakePoolData, tokens, AccountNonce,
        AccountSpending,
    },
    primitives::per_thousand::PerThousand,
};
use crypto::vrf::{VRFPrivateKey, VRFPublicKey};
use pos_accounting::DelegationData;
use tokens_accounting::TokenData;

mod mocks;

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
}

impl TestInputInfo {
    const fn utxo(outpoint: UtxoOutPoint, utxo: utxo::Utxo) -> Self {
        Self::Utxo { outpoint, utxo }
    }

    fn to_input_info(&self) -> InputInfo<'_> {
        match self {
            Self::Utxo { outpoint, utxo } => InputInfo::Utxo {
                outpoint,
                utxo: utxo.clone(),
            },
            Self::Account { outpoint } => InputInfo::Account { outpoint },
            Self::AccountCommand { command } => InputInfo::AccountCommand { command },
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

fn nosig() -> InputWitness {
    InputWitness::NoSignature(None)
}

fn stdsig(byte: u8) -> InputWitness {
    let sht = SigHashType::default();
    InputWitness::Standard(StandardInputSignature::new(sht, vec![byte; 2]))
}

fn deleg0() -> (DelegationId, DelegationData) {
    let data = DelegationData::new(fake_id(0x57), dest_pk(101));
    (fake_id(0x75), data)
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

// A hack to specify all the modes in the parametrized test below. The mode specification ought to
// be simplified in the actual implementation and then this may be dropped.

trait TranslationMode<'b> {
    const NAME: &'static str;
    type Mode: for<'a> TranslateInput<MockSigInfoProvider<'a>> + 'b;
    fn translate_input_and_witness(
        &self,
        info: &mocks::MockSigInfoProvider,
    ) -> Result<WitnessScript, TranslationError> {
        Self::Mode::translate_input(info)
    }
}

struct TxnMode;
impl TranslationMode<'_> for TxnMode {
    const NAME: &'static str = "txn";
    type Mode = SignedTransaction;
}

struct RewardMode;
impl<'a> TranslationMode<'a> for RewardMode {
    const NAME: &'static str = "reward";
    type Mode = BlockRewardTransactable<'a>;
}

impl TranslationMode<'_> for TimelockOnly {
    const NAME: &'static str = "tlockonly";
    type Mode = Self;
}

fn mode_name<'a, T: TranslationMode<'a>>(_: &T) -> &'static str {
    T::NAME
}

// The test itself

#[rstest::rstest]
#[case("burn_00", burn(100_000), nosig())]
#[case("burn_01", burn(200_000), stdsig(0x51))]
#[case("transfer_00", transfer_pk(12, 555), nosig())]
#[case("transfer_01", transfer_pk(13, 557), stdsig(0x51))]
#[case("transfer_02", transfer_pkh(0x12, 300_000), stdsig(0x52))]
#[case("transfer_03", transfer_pkh(0x12, 300_000), nosig())]
#[case(
    "transfertl_00",
    transfer_pk_tl(12, 555, tl_for_blocks(600)),
    stdsig(0x5d)
)]
#[case(
    "transfertl_01",
    transfer_pk_tl(13, 557, tl_until_height(155_554)),
    stdsig(0x59)
)]
#[case(
    "transfertl_02",
    transfer_pk_tl(14, 558, tl_for_secs(365 * 24 * 60 * 60)),
    stdsig(0x5a),
)]
#[case(
    "transfertl_03",
    transfer_pk_tl(15, 559, tl_until_time(1_718_120_714)),
    stdsig(0x5b)
)]
#[case(
    "transfertl_04",
    transfer_pk_tl(16, 560, tl_until_height(999_999)),
    nosig()
)]
#[case("newpool_00", create_pool(14, 15), stdsig(0x53))]
#[case("acctspend_00", account_spend(deleg0().0, 579), stdsig(0x54))]
#[case("acctspend_01", account_spend(fake_id(0xf5), 580), stdsig(0x55))]
#[case("acctspend_02", account_spend(deleg0().0, 581), nosig())]
#[case("mint_00", mint(fake_id(0xa1), 581), stdsig(0x56))]
#[case("mint_01", mint(token0().0, 582), stdsig(0x57))]
#[case("mint_02", mint(token0().0, 582), nosig())]
fn translate_snap(
    #[values(TxnMode, RewardMode, TimelockOnly)] mode: impl for<'a> TranslationMode<'a>,
    #[case] name: &str,
    #[case] test_input_info: TestInputInfo,
    #[case] witness: InputWitness,
) {
    let input_info = test_input_info.to_input_info();
    let tokens = [token0()];
    let delegs = [deleg0()];
    let sig_info = mocks::MockSigInfoProvider::new(input_info, witness, tokens, [], delegs);
    let mode_str = mode_name(&mode);

    let result = match mode.translate_input_and_witness(&sig_info) {
        Ok(script) => format!("{script:#?}"),
        Err(err) => format!("ERROR: {err}"),
    };

    expect_test::expect_file![format!("snap.translate.{mode_str}.{name}.txt")].assert_eq(&result);
}
