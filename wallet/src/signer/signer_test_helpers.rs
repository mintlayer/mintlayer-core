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

use std::ops::{Add, Div, Sub};
use std::sync::Arc;

use common::chain::htlc::{HashedTimelockContract, HtlcSecret};
use common::chain::stakelock::StakePoolData;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::{NftIssuance, NftIssuanceV0, TokenId, TokenIssuance};
use common::chain::{
    AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, DelegationId, OrderData,
    OutPointSourceId, PoolId,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::BlockHeight;
use common::{
    chain::{
        config::create_regtest,
        output_value::OutputValue,
        signature::{inputsig::arbitrary_message::produce_message_challenge, DestinationSigError},
        ChainConfig, Destination, GenBlock, SignedTransactionIntent, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, Id, H256},
};
use crypto::key::hdkd::u31::U31;
use crypto::key::{KeyKind, PrivateKey};
use itertools::izip;
use randomness::{CryptoRng, Rng};
use tx_verifier::error::{InputCheckErrorPayload, ScriptError};
use wallet_storage::{DefaultBackend, Store, StoreTxRwUnlocked, Transactional};
use wallet_types::partially_signed_transaction::{
    OrderAdditionalInfo, TokenAdditionalInfo, TxAdditionalInfo,
};
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, seed_phrase::StoreSeedPhrase, KeyPurpose};

use crate::key_chain::AccountKeyChainImplSoftware;
use crate::signer::SignerError;
use crate::SendRequest;
use crate::{
    key_chain::{MasterKeyChain, LOOKAHEAD_SIZE},
    Account,
};

use super::Signer;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub fn test_sign_message<F, S>(rng: &mut (impl Rng + CryptoRng), make_signer: F)
where
    F: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);

    let pkh_destination = account
        .get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds)
        .unwrap()
        .1
        .into_object();
    let pkh = match pkh_destination {
        Destination::PublicKeyHash(pkh) => pkh,
        _ => panic!("not a public key hash destination"),
    };
    let pk = account.find_corresponding_pub_key(&pkh).unwrap();
    let pk_destination = Destination::PublicKey(pk);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk);

    for destination in [pkh_destination, pk_destination, standalone_pk_destination] {
        let mut signer = make_signer(chain_config.clone(), account.account_index());

        let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
        let res = signer
            .sign_challenge(&message, &destination, account.key_chain(), &db_tx)
            .unwrap();

        let message_challenge = produce_message_challenge(&message);
        res.verify_signature(&chain_config, &destination, &message_challenge).unwrap();
    }

    // Check we cannot signe if we don't know the destination
    let (_, random_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let random_pk_destination = Destination::PublicKey(random_pk);

    let mut signer = make_signer(chain_config.clone(), account.account_index());

    let message = vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
    let err = signer
        .sign_challenge(
            &message,
            &random_pk_destination,
            account.key_chain(),
            &db_tx,
        )
        .unwrap_err();

    assert_eq!(err, SignerError::DestinationNotFromThisWallet);
}

pub fn test_sign_transaction_intent<F, S>(rng: &mut (impl Rng + CryptoRng), make_signer: F)
where
    F: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
    use common::primitives::Idable;

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk);

    let mut signer = make_signer(chain_config.clone(), account.account_index());

    let inputs: Vec<TxInput> = (0..rng.gen_range(3..6))
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();
    let num_inputs = inputs.len();
    let mut input_destinations: Vec<_> = (1..num_inputs)
        .map(|_| {
            let pkh_destination = account
                .get_new_address(&mut db_tx, KeyPurpose::ReceiveFunds)
                .unwrap()
                .1
                .into_object();
            if rng.gen::<bool>() {
                pkh_destination
            } else {
                let pkh = match pkh_destination {
                    Destination::PublicKeyHash(pkh) => pkh,
                    _ => panic!("not a public key hash destination"),
                };
                let pk = account.find_corresponding_pub_key(&pkh).unwrap();
                Destination::PublicKey(pk)
            }
        })
        .chain([standalone_pk_destination])
        .collect();

    let tx = Transaction::new(
        0,
        inputs,
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            account.get_new_address(&mut db_tx, KeyPurpose::Change).unwrap().1.into_object(),
        )],
    )
    .unwrap();

    let intent: String = [rng.gen::<char>(), rng.gen::<char>(), rng.gen::<char>()].iter().collect();
    let res = signer
        .sign_transaction_intent(
            &tx,
            &input_destinations,
            &intent,
            account.key_chain(),
            &db_tx,
        )
        .unwrap();

    let expected_signed_message =
        SignedTransactionIntent::get_message_to_sign(&intent, &tx.get_id());
    res.verify(&chain_config, &input_destinations, &expected_signed_message)
        .unwrap();

    // cannot sign when there is a random destination
    let (_, random_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let random_pk_destination = Destination::PublicKey(random_pk);
    input_destinations[rng.gen_range(0..num_inputs)] = random_pk_destination;

    let err = signer
        .sign_transaction_intent(
            &tx,
            &input_destinations,
            &intent,
            account.key_chain(),
            &db_tx,
        )
        .unwrap_err();

    assert_eq!(err, SignerError::DestinationNotFromThisWallet);
}

pub fn test_sign_transaction<F, S>(rng: &mut (impl Rng + CryptoRng), make_signer: F)
where
    F: Fn(Arc<ChainConfig>, U31) -> S,
    S: Signer,
{
    use std::num::NonZeroU8;

    use common::{
        chain::{
            classic_multisig::ClassicMultisigChallenge,
            tokens::{IsTokenUnfreezable, Metadata, TokenIssuanceV1},
            OrderId,
        },
        primitives::amount::UnsignedIntType,
    };
    use crypto::vrf::VRFPrivateKey;
    use serialization::extras::non_empty_vec::DataOrNoVec;

    let chain_config = Arc::new(create_regtest());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let mut account = account_from_mnemonic(&chain_config, &mut db_tx, DEFAULT_ACCOUNT_INDEX);
    let mut account2 = account_from_mnemonic(&chain_config, &mut db_tx, U31::ONE);

    let (standalone_private_key, standalone_pk) =
        PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    account
        .add_standalone_private_key(&mut db_tx, standalone_private_key, None)
        .unwrap();
    let standalone_pk_destination = Destination::PublicKey(standalone_pk.clone());

    let amounts: Vec<Amount> = (0..(2 + rng.next_u32() % 5))
        .map(|_| Amount::from_atoms(rng.gen_range(10..100) as UnsignedIntType))
        .collect();

    let total_amount = amounts.iter().fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());
    eprintln!("total utxo amounts: {total_amount:?}");

    let utxos: Vec<TxOutput> = amounts
        .iter()
        .skip(1)
        .map(|a| {
            let dest = {
                let purpose = if rng.gen_bool(0.5) {
                    KeyPurpose::ReceiveFunds
                } else {
                    KeyPurpose::Change
                };

                account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object()
            };

            TxOutput::Transfer(OutputValue::Coin(*a), dest)
        })
        .chain([TxOutput::Transfer(
            OutputValue::Coin(amounts[0]),
            standalone_pk_destination.clone(),
        )])
        .collect();

    let inputs: Vec<TxInput> = (0..utxos.len())
        .map(|_| {
            let source_id = if rng.gen_bool(0.5) {
                Id::<Transaction>::new(H256::random_using(rng)).into()
            } else {
                Id::<GenBlock>::new(H256::random_using(rng)).into()
            };
            TxInput::from_utxo(source_id, rng.next_u32())
        })
        .collect();

    let (_dest_prv, pub_key1) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let pub_key2 = if let Destination::PublicKeyHash(pkh) =
        account.get_new_address(&mut db_tx, KeyPurpose::Change).unwrap().1.into_object()
    {
        account.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };
    let pub_key3 = if let Destination::PublicKeyHash(pkh) = account2
        .get_new_address(&mut db_tx, KeyPurpose::Change)
        .unwrap()
        .1
        .into_object()
    {
        account2.find_corresponding_pub_key(&pkh).unwrap()
    } else {
        panic!("not a public key hash")
    };

    let min_required_signatures = 3;
    // The first account can signe the pub_key2 and the standalone key,
    // but it will not be fully signed, so we will need to signe it with the account2 which
    // can conplete the signing with the pub_key3
    let challenge = ClassicMultisigChallenge::new(
        &chain_config,
        NonZeroU8::new(min_required_signatures).unwrap(),
        vec![pub_key1.clone(), pub_key2.clone(), standalone_pk, pub_key3.clone()],
    )
    .unwrap();
    account.add_standalone_multisig(&mut db_tx, challenge.clone(), None).unwrap();
    let multisig_hash = account2.add_standalone_multisig(&mut db_tx, challenge, None).unwrap();

    let multisig_dest = Destination::ClassicMultisig(multisig_hash);

    let source_id: OutPointSourceId = if rng.gen_bool(0.5) {
        Id::<Transaction>::new(H256::random_using(rng)).into()
    } else {
        Id::<GenBlock>::new(H256::random_using(rng)).into()
    };
    let multisig_input = TxInput::from_utxo(source_id.clone(), rng.next_u32());
    let multisig_utxo = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1)),
        multisig_dest.clone(),
    );

    let secret = HtlcSecret::new_from_rng(rng);
    let hash_lock = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::PublicKey(pub_key2.clone()),
        refund_timelock: OutputTimeLock::UntilHeight(BlockHeight::new(0)),
        refund_key: Destination::PublicKey(pub_key1),
    };

    let htlc_input = TxInput::from_utxo(source_id, rng.next_u32());
    let htlc_utxo = TxOutput::Htlc(
        OutputValue::Coin(Amount::from_atoms(rng.gen::<u32>() as u128)),
        Box::new(hash_lock.clone()),
    );

    let token_id = TokenId::new(H256::random_using(rng));
    let order_id = OrderId::new(H256::random_using(rng));

    let dest_amount = total_amount.div(10).unwrap();
    let lock_amount = total_amount.div(10).unwrap();
    let burn_amount = total_amount.div(10).unwrap();
    let change_amount = total_amount.div(10).unwrap();
    let outputs_amounts_sum = [dest_amount, lock_amount, burn_amount, change_amount]
        .iter()
        .fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());
    let _fee_amount = total_amount.sub(outputs_amounts_sum).unwrap();

    let acc_inputs = vec![
        TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(1),
            AccountSpending::DelegationBalance(
                DelegationId::new(H256::random_using(rng)),
                Amount::from_atoms(1_u128),
            ),
        )),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::MintTokens(token_id, (dest_amount + Amount::from_atoms(100)).unwrap()),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnmintTokens(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::LockTokenSupply(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::UnfreezeToken(token_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenAuthority(
                TokenId::new(H256::random_using(rng)),
                Destination::AnyoneCanSpend,
            ),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ConcludeOrder(order_id),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::FillOrder(order_id, Amount::from_atoms(1), Destination::AnyoneCanSpend),
        ),
        TxInput::AccountCommand(
            AccountNonce::new(rng.next_u64()),
            AccountCommand::ChangeTokenMetadataUri(
                TokenId::new(H256::random_using(rng)),
                "http://uri".as_bytes().to_vec(),
            ),
        ),
    ];
    let acc_dests: Vec<Destination> = acc_inputs
        .iter()
        .map(|_| {
            let purpose = if rng.gen_bool(0.5) {
                KeyPurpose::ReceiveFunds
            } else {
                KeyPurpose::Change
            };

            account.get_new_address(&mut db_tx, purpose).unwrap().1.into_object()
        })
        .collect();

    let (_dest_prv, dest_pub) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (_, vrf_public_key) = VRFPrivateKey::new_from_rng(rng, crypto::vrf::VRFKeyKind::Schnorrkel);

    let pool_id = PoolId::new(H256::random_using(rng));
    let delegation_id = DelegationId::new(H256::random_using(rng));
    let pool_data = StakePoolData::new(
        Amount::from_atoms(5),
        Destination::PublicKey(dest_pub.clone()),
        vrf_public_key,
        Destination::PublicKey(dest_pub.clone()),
        PerThousand::new_from_rng(rng),
        Amount::from_atoms(100),
    );
    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: "XXXX".as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: "http://uri".as_bytes().to_vec(),
        total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
        authority: Destination::PublicKey(dest_pub.clone()),
        is_freezable: common::chain::tokens::IsTokenFreezable::No,
    });

    let nft_issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: "Name".as_bytes().to_vec(),
            description: "SomeNFT".as_bytes().to_vec(),
            ticker: "NFTX".as_bytes().to_vec(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: "123456".as_bytes().to_vec(),
        },
    });
    let nft_id = TokenId::new(H256::random_using(rng));

    let order_data = OrderData::new(
        Destination::PublicKey(dest_pub.clone()),
        OutputValue::Coin(Amount::from_atoms(100)),
        OutputValue::Coin(total_amount),
    );

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::TokenV1(token_id, dest_amount),
            Destination::PublicKey(dest_pub.clone()),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(dest_amount),
            Destination::PublicKey(dest_pub),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(lock_amount),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForSeconds(rng.next_u64()),
        ),
        TxOutput::Burn(OutputValue::Coin(burn_amount)),
        TxOutput::CreateStakePool(pool_id, Box::new(pool_data)),
        TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            PoolId::new(H256::random_using(rng)),
        ),
        TxOutput::DelegateStaking(burn_amount, delegation_id),
        TxOutput::IssueFungibleToken(Box::new(token_issuance)),
        TxOutput::IssueNft(
            nft_id,
            Box::new(nft_issuance.clone()),
            Destination::AnyoneCanSpend,
        ),
        TxOutput::DataDeposit(vec![1, 2, 3]),
        TxOutput::Htlc(OutputValue::Coin(burn_amount), Box::new(hash_lock)),
        TxOutput::CreateOrder(Box::new(order_data)),
    ];

    let req = SendRequest::new()
        .with_inputs(
            izip!(inputs.clone(), utxos.clone(), vec![None; inputs.len()]),
            &|_| None,
        )
        .unwrap()
        .with_inputs(
            [(htlc_input.clone(), htlc_utxo.clone(), Some(secret))],
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
    let additional_info = TxAdditionalInfo::with_token_info(
        token_id,
        TokenAdditionalInfo {
            num_decimals: 1,
            ticker: "TKN".as_bytes().to_vec(),
        },
    )
    .join(TxAdditionalInfo::with_order_info(
        order_id,
        OrderAdditionalInfo {
            ask_balance: Amount::from_atoms(10),
            give_balance: Amount::from_atoms(100),
            initially_asked: OutputValue::Coin(Amount::from_atoms(20)),
            initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(200)),
        },
    ));
    let ptx = req.into_partially_signed_tx(additional_info).unwrap();

    let mut signer = make_signer(chain_config.clone(), account.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account.key_chain(), &db_tx).unwrap();

    assert!(ptx.all_signatures_available());

    let utxos_ref = utxos
        .iter()
        .map(Some)
        .chain([Some(&htlc_utxo), Some(&multisig_utxo)])
        .chain(acc_dests.iter().map(|_| None))
        .collect::<Vec<_>>();

    for (i, dest) in destinations.iter().enumerate() {
        // the multisig will not be fully signed
        if dest == &multisig_dest {
            let err = tx_verifier::input_check::signature_only_check::verify_tx_signature(
                &chain_config,
                dest,
                &ptx,
                &utxos_ref,
                i,
            )
            .unwrap_err();
            assert_eq!(
                err.error(),
                &InputCheckErrorPayload::Verification(ScriptError::Signature(
                    DestinationSigError::IncompleteClassicalMultisigSignature(
                        min_required_signatures,
                        min_required_signatures - 1
                    )
                )),
            )
        } else {
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

    // fully sign the remaining key in the multisig address
    let mut signer = make_signer(chain_config.clone(), account2.account_index());
    let (ptx, _, _) = signer.sign_tx(ptx, account2.key_chain(), &db_tx).unwrap();

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

fn account_from_mnemonic<B: storage::Backend>(
    chain_config: &Arc<ChainConfig>,
    db_tx: &mut StoreTxRwUnlocked<B>,
    account_index: U31,
) -> Account<AccountKeyChainImplSoftware> {
    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(db_tx, account_index, LOOKAHEAD_SIZE)
        .unwrap();
    Account::new(chain_config.clone(), db_tx, key_chain, None).unwrap()
}
