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

use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use common::chain::{config::create_mainnet, ChainConfig, SighashInputCommitmentVersion};
use crypto::key::{
    hdkd::{derivation_path::DerivationPath, u31::U31},
    PredefinedSigAuxDataProvider, SigAuxDataProvider,
};
use ledger_lib::{
    transport::{TcpDevice, TcpInfo, TcpTransport},
    Transport,
};
use logging::log;
use randomness::make_true_rng;
use rstest::rstest;
use serialization::hex::HexEncode;
use test_utils::random::{make_seedable_rng, Seed};
use tokio::{
    sync::{
        mpsc::{self, Sender},
        Mutex,
    },
    time::sleep,
};
use wallet_storage::WalletStorageReadLocked;
use wallet_types::hw_data::LedgerData;

use crate::signer::{
    ledger_signer::{
        ledger_messages::get_extended_public_key,
        speculus::{
            Action, Button, Display, Driver, Handle, Model, Options, PodmanDriver, PodmanHandle,
        },
        LProvider, LedgerError, LedgerSigner,
    },
    tests::{
        generic_tests::{
            test_sign_transaction_generic, test_sign_transaction_intent_generic, MessageToSign,
        },
        no_another_signer,
    },
    SignerError, SignerResult,
};

#[derive(Debug)]
enum ControlMessage {
    Finish,
}

async fn auto_confirmer(
    mut finish_rx: mpsc::Receiver<ControlMessage>,
    handle: PodmanHandle,
    driver: PodmanDriver,
) {
    loop {
        tokio::select! {
            _ = sleep(Duration::from_millis(100)) => {
                handle.button(Button::Right, Action::PressAndRelease).await.unwrap();
                handle.button(Button::Both, Action::PressAndRelease).await.unwrap();
            }
            msg = finish_rx.recv() => {
                match msg {
                    Some(ControlMessage::Finish) => {
                        eprintln!("Received finish signal.");
                        // perform exit action
                        driver.exit(handle).unwrap();
                        break;
                    }
                    None => {
                        eprintln!("Channel closed.");
                        break;
                    }
                }
            }
        }
    }

    println!("Auto-confirmer task finished.");
}

struct DummyProvider;

#[async_trait]
impl LProvider for DummyProvider {
    type L = TcpDevice;

    async fn find_ledger_device_from_db<T: WalletStorageReadLocked + Send>(
        &self,
        _db_tx: &mut T,
    ) -> SignerResult<(Self::L, LedgerData)> {
        Err(SignerError::LedgerError(LedgerError::NoDeviceFound))
    }
}

async fn setup(
    offset: u16,
    deterministic_aux: bool,
) -> (
    tokio::task::JoinHandle<()>,
    Sender<ControlMessage>,
    impl Fn(Arc<ChainConfig>, U31) -> LedgerSigner<TcpDevice, DummyProvider>,
) {
    let driver = PodmanDriver::new().unwrap();

    let opts = Options {
        model: Model::NanoSP,
        api_level: Some("24".to_string()),
        seed: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()), // Use a deterministic seed for tests
        display: Display::Headless,
        apdu_port: Some(1237 + offset),
        http_port: 5001 + offset,
        ..Default::default()
    };

    let app_path = format!(
        "{}/../../ledger-mintlayer/target/nanosplus/release/mintlayer-app",
        env!("CARGO_MANIFEST_DIR")
    );
    let handle = driver.run(&app_path, opts.clone()).unwrap();

    println!("Emulator is running...");

    // TODO: instead of sleeping try to connect and wait for a successfull connection to the
    // docker
    sleep(Duration::from_secs(5)).await;

    let mut transport = TcpTransport::new().unwrap();
    let device = transport
        .connect(TcpInfo {
            addr: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                1237 + offset,
            ),
        })
        .await
        .unwrap();

    let device = Arc::new(Mutex::new(device));

    let (finish_tx, finish_rx) = mpsc::channel(1);
    let auto_clicker = tokio::spawn(auto_confirmer(finish_rx, handle, driver));

    (auto_clicker, finish_tx, move |chain_config, _| {
        let aux_provider: Box<dyn SigAuxDataProvider + Send> = if deterministic_aux {
            Box::new(PredefinedSigAuxDataProvider)
        } else {
            Box::new(make_true_rng())
        };

        LedgerSigner::new_with_sig_aux_data_provider(
            chain_config,
            device.clone(),
            aux_provider,
            DummyProvider {},
        )
    })
}

#[rstest]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_account_extended_public_key() {
    let (auto_clicker, finish_tx, make_ledger_signer) = setup(1, false).await;

    let signer = make_ledger_signer(Arc::new(create_mainnet()), U31::ZERO);

    let derivation_path = DerivationPath::from_str("m/44h/19788h/0h").unwrap();
    let (public_key, chain_code) =
        get_extended_public_key(&mut *signer.client.lock().await, 0, derivation_path)
            .await
            .unwrap()
            .into_public_key_and_chain_code();

    let expected_pk = "029103888be8638b733d54eba6c5a96ae12583881dfab4b9585366548b54e3f8fd";
    assert_eq!(
        expected_pk,
        public_key.hex_encode().strip_prefix("00").unwrap()
    );

    let expected_chain_code = "0b71f99e82c97a4c8f75d8d215e7260bcf9e964d437ec252af26877adf7e8683";
    assert_eq!(expected_chain_code, chain_code.hex_encode());

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message(
    #[case] seed: Seed,
    #[values(
        MessageToSign::Random,
        // Special case: an "overlong" utf-8 string (basically, the letter 'K' encoded with 2 bytes
        // instead of 1). The firmware used to have troubles with this.
        MessageToSign::Predefined(vec![193, 139])
    )]
    message_to_sign: MessageToSign,
) {
    use crate::signer::tests::generic_tests::test_sign_message_generic;

    log::debug!("test_sign_transaction_intent, seed = {seed:?}");

    let mut rng = make_seedable_rng(seed);

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(2, false).await;

    test_sign_message_generic(
        &mut rng,
        message_to_sign,
        make_ledger_signer,
        no_another_signer(),
    )
    .await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent(#[case] seed: Seed) {
    log::debug!("test_sign_transaction_intent, seed = {seed:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(3, false).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(&mut rng, make_ledger_signer, no_another_signer()).await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_sign_transaction, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(4, false).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_ledger_signer,
        no_another_signer(),
    )
    .await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_fixed_signatures2(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    use crate::signer::tests::generic_fixed_signature_tests::test_fixed_signatures_generic2;

    log::debug!("test_fixed_signatures2, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(6, true).await;

    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic2(&mut rng, input_commitments_version, make_ledger_signer).await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message_sig_consistency(#[case] seed: Seed) {
    use crate::signer::tests::{
        generic_tests::test_sign_message_generic, make_deterministic_software_signer,
    };

    log::debug!("test_sign_message_sig_consistency, seed = {seed:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(7, true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_message_generic(
        &mut rng,
        MessageToSign::Random,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
    )
    .await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent_sig_consistency(#[case] seed: Seed) {
    use crate::signer::tests::make_deterministic_software_signer;

    log::debug!("test_sign_transaction_intent_sig_consistency, seed = {seed:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(8, true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(
        &mut rng,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
    )
    .await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_sig_consistency(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    use crate::signer::tests::make_deterministic_software_signer;

    log::debug!("test_sign_transaction_sig_consistency, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let (auto_clicker, finish_tx, make_ledger_signer) = setup(9, true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
    )
    .await;

    finish_tx.send(ControlMessage::Finish).await.unwrap();
    auto_clicker.await.unwrap();
}
