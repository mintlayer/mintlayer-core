// Copyright (c) 2025 RBB S.r.l
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

use std::{num::NonZeroU8, sync::Arc};

use itertools::izip;

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        config::create_regtest,
        htlc::HashedTimelockContract,
        output_value::OutputValue,
        signature::{
            inputsig::{
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance,
            TokenIssuanceV1,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId, Destination,
        OrderData, OrderId, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, H256},
};
use crypto::{
    key::{secp256k1::Secp256k1PublicKey, PublicKey, Signature},
    vrf::VRFPrivateKey,
};
use serialization::{extras::non_empty_vec::DataOrNoVec, Encode as _};
use wallet_storage::{DefaultBackend, Store, Transactional};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX, partially_signed_transaction::TxAdditionalInfo,
    seed_phrase::StoreSeedPhrase, KeyPurpose,
};

use crate::{
    key_chain::{MasterKeyChain, LOOKAHEAD_SIZE},
    signer::tests::MNEMONIC,
    Account, SendRequest,
};

// Verify some signatures produced on a Trezor.
#[test]
fn fixed_trezor_signatures() {
    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    let mut account = Account::new(chain_config.clone(), &mut db_tx, key_chain, None).unwrap();

    let amount_1 = Amount::from_atoms(1);
    let random_pk = PublicKey::from(
        Secp256k1PublicKey::from_bytes(&[
            2, 2, 11, 98, 44, 24, 95, 8, 36, 172, 134, 193, 94, 60, 66, 115, 65, 190, 73, 45, 12,
            228, 65, 185, 175, 158, 4, 233, 125, 192, 84, 52, 242,
        ])
        .unwrap(),
    );

    eprintln!("getting first address");
    let (num, addr) = account.get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds).unwrap();
    eprintln!("num: {num:?}");

    let wallet_pk0 = if let Destination::PublicKeyHash(pkh) = addr.into_object() {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };

    let wallet_pk1 = if let Destination::PublicKeyHash(pkh) = account
        .get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds)
        .unwrap()
        .1
        .into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let min_required_signatures = 2;
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![wallet_pk0.clone(), random_pk, wallet_pk1],
    )
    .unwrap();
    let multisig_hash =
        account.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();

    let multisig_dest = Destination::ClassicMultisig(multisig_hash);

    let multisig_input = TxInput::from_utxo(Id::<Transaction>::new(H256::zero()).into(), 2);
    let multisig_utxo = TxOutput::Transfer(OutputValue::Coin(amount_1), multisig_dest);

    let delegation_id = DelegationId::new(H256::zero());
    let token_id = TokenId::new(H256::zero());
    let order_id = OrderId::new(H256::zero());
    let pool_id = PoolId::new(H256::zero());

    let uri = "http://uri.com".as_bytes().to_vec();

    let wallet_dest0 = Destination::PublicKeyHash((&wallet_pk0).into());

    let utxos = [TxOutput::Transfer(OutputValue::Coin(amount_1), wallet_dest0.clone())];

    let inputs = [TxInput::from_utxo(
        OutPointSourceId::Transaction(Id::<Transaction>::new(H256::zero())),
        1,
    )];

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(delegation_id, amount_1),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::MintTokens(token_id, amount_1),
        ),
        TxInput::AccountCommand(AccountNonce::new(0), AccountCommand::UnmintTokens(token_id)),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::LockTokenSupply(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::UnfreezeToken(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ConcludeOrder(order_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FillOrder(order_id, amount_1, Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenMetadataUri(token_id, uri.clone()),
        ),
    ];
    let acc_dests: Vec<Destination> = vec![wallet_dest0.clone(); acc_inputs.len()];

    let (_, vrf_public_key) =
        VRFPrivateKey::new_using_random_bytes(&[0; 32], crypto::vrf::VRFKeyKind::Schnorrkel)
            .unwrap();

    let pool_data = StakePoolData::new(
        amount_1,
        Destination::AnyoneCanSpend,
        vrf_public_key,
        Destination::AnyoneCanSpend,
        PerThousand::new(1).unwrap(),
        amount_1,
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: 2,
        metadata_uri: uri.clone(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: Destination::AnyoneCanSpend,
        is_freezable: common::chain::tokens::IsTokenFreezable::Yes,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: "Name".as_bytes().to_vec(),
            description: "SomeNFT".as_bytes().to_vec(),
            ticker: "NFTX".as_bytes().to_vec(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: Some(uri).into(),
            media_hash: "123456".as_bytes().to_vec(),
        },
    });
    let hash_lock = HashedTimelockContract {
        secret_hash: common::chain::htlc::HtlcSecretHash([1; 20]),
        spend_key: Destination::AnyoneCanSpend,
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(10)),
        refund_key: Destination::AnyoneCanSpend,
    };

    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(amount_1),
        OutputValue::Coin(amount_1),
    );

    let outputs = vec![
        TxOutput::Transfer(OutputValue::Coin(amount_1), Destination::AnyoneCanSpend),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::UntilHeight(BlockHeight::new(10)),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(10)),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(10),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_1),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(10),
        ),
        TxOutput::Burn(OutputValue::Coin(amount_1)),
        TxOutput::CreateStakePool(pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, pool_id),
        TxOutput::DelegateStaking(amount_1, delegation_id),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            token_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(vec![1, 2, 3]),
        TxOutput::Htlc(OutputValue::Coin(amount_1), Box::new(hash_lock)),
        TxOutput::CreateOrder(Box::new(order_data)),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(inputs.clone(), utxos.clone(), vec![None; inputs.len()]),
            &|_| None,
        )
        .unwrap()
        .with_inputs(
            [(multisig_input.clone(), multisig_utxo.clone(), None)],
            &|_| None,
        )
        .unwrap()
        .with_inputs_and_destinations(acc_inputs.into_iter().zip(acc_dests.clone()))
        .with_outputs(outputs);
    let destinations = req.destinations().to_vec();
    let additional_info = TxAdditionalInfo::new();
    let ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let utxos_ref = utxos
        .iter()
        .map(Some)
        .chain([Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    let multisig_signatures = [
        (0, "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59"),
        (2, "0a0a17d71bc98fa5c24ea611c856d0d08c6a765ea3c4c8f068668e0bdff710b82b0d2eead83d059386cd3cbdf4308418d4b81e6f52c001a9141ec477a8d24845"),
    ];

    let mut current_signatures = AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

    for (idx, sig) in multisig_signatures {
        let mut signature = hex::decode(sig).unwrap();
        signature.insert(0, 0);
        let sig = Signature::from_data(signature).unwrap();
        current_signatures.add_signature(idx as u8, sig);
    }

    let sighash_type: SigHashType = SigHashType::ALL.try_into().unwrap();
    let multisig_sig = StandardInputSignature::new(sighash_type, current_signatures.encode());

    let sig = "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59";
    let mut bytes = hex::decode(sig).unwrap();
    bytes.insert(0, 0);

    let sig = Signature::from_data(bytes).unwrap();
    let sig = AuthorizedPublicKeyHashSpend::new(wallet_pk0.clone(), sig);
    let sig = StandardInputSignature::new(SigHashType::ALL.try_into().unwrap(), sig.encode());

    let mut sigs = vec![Some(InputWitness::Standard(sig)); ptx.count_inputs()];
    sigs[1] = Some(InputWitness::Standard(multisig_sig));
    let ptx = ptx.with_witnesses(sigs);

    assert!(ptx.all_signatures_available());

    for (i, dest) in destinations.iter().enumerate() {
        tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &chain_config,
            dest,
            &ptx,
            &utxos_ref,
            i,
        )
        .unwrap();
    }
}
