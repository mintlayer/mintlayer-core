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

mod speculos;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use ledger_lib::{
    transport::{TcpDevice, TcpInfo, TcpTransport},
    Device as _, Transport,
};
use mintlayer_ledger_messages::CoinType;
use rstest::rstest;
use tokio::{
    sync::{
        mpsc::{self, Sender},
        Mutex,
    },
    time::sleep,
};

use crate::signer::{
    ledger_signer::{
        ledger_messages::{
            check_current_app, get_extended_public_key, get_extended_public_key_raw,
        },
        LedgerError, LedgerFinder, LedgerSigner,
    },
    tests::{
        generic_fixed_signature_tests::test_fixed_signatures_generic_no_legacy,
        generic_tests::{
            sign_message_test_params, test_sign_message_generic, test_sign_transaction_generic,
            test_sign_transaction_intent_generic, MessageToSign,
        },
        make_deterministic_software_signer, no_another_signer,
    },
    SignerError, SignerResult,
};
use common::chain::{config::create_mainnet, ChainConfig, SighashInputCommitmentVersion};
use crypto::key::{
    hdkd::{derivation_path::DerivationPath, u31::U31},
    PredefinedSigAuxDataProvider, SigAuxDataProvider,
};
use logging::log;
use randomness::make_true_rng;
use serialization::hex::HexEncode;
use speculos::{Device, Handle};
use test_utils::random::{make_seedable_rng, Seed};
use utils::env_utils::{bool_from_env, get_from_env};
use wallet_storage::WalletStorageReadLocked;
use wallet_types::hw_data::LedgerData;

#[derive(Debug)]
enum ControlMessage {
    Finish,
}

fn emulator_api_port() -> u16 {
    get_from_env("LEDGER_TESTS_EMU_API_PORT")
        .unwrap()
        .map_or(5000, |s| s.parse().unwrap())
}

fn emulator_apdu_port() -> u16 {
    get_from_env("LEDGER_TESTS_EMU_APDU_PORT")
        .unwrap()
        .map_or(9999, |s| s.parse().unwrap())
}

fn should_auto_confirm() -> bool {
    bool_from_env("LEDGER_TESTS_AUTO_CONFIRM").unwrap().unwrap_or(false)
}

async fn auto_confirmer(mut control_msg_rx: mpsc::Receiver<ControlMessage>, handle: Handle) {
    println!("Starting auto-confirmer for device: {:?}", handle.device());

    loop {
        tokio::select! {
            _ = sleep(Duration::from_millis(500)) => {
                if let Ok(events) = handle.current_screen_events().await {
                    let to_sign = events.iter().any(|e| e.contains("Sign "));

                    if to_sign {
                        let _ = handle.confirm().await;
                    } else {
                        let _ = handle.navigate_next().await;
                    }
                }
            }
            msg = control_msg_rx.recv() => {
                match msg {
                    Some(ControlMessage::Finish) => {
                        eprintln!("Received finish signal.");
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
impl LedgerFinder for DummyProvider {
    type Ledger = TcpDevice;

    async fn find_ledger_device_from_db<T: WalletStorageReadLocked + Send>(
        &self,
        _db_tx: &mut T,
        _chain_config: Arc<ChainConfig>,
    ) -> SignerResult<(Self::Ledger, LedgerData)> {
        Err(SignerError::LedgerError(LedgerError::NoDeviceFound))
    }
}

async fn wait_for_valid_reponse(device: &mut TcpDevice) {
    let mut tries = 0;
    let derivation_path = DerivationPath::from_str("m/44h/19788h/0h").unwrap();
    loop {
        match get_extended_public_key_raw(device, CoinType::Mainnet, &derivation_path).await {
            Ok(_) => break,
            Err(_) => {
                tries += 1;
                assert!(
                    tries <= 10,
                    "Could not get a valid response from the device"
                );
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn setup(
    deterministic_signing: bool,
) -> (
    Option<tokio::task::JoinHandle<()>>,
    Sender<ControlMessage>,
    impl Fn(Arc<ChainConfig>, U31) -> LedgerSigner<TcpDevice, DummyProvider>,
) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), emulator_api_port());

    let device_model_env: String = get_from_env("LEDGER_TESTS_DEVICE_MODEL")
        .expect("Failed to read env var LEDGER_TESTS_DEVICE_MODEL")
        .unwrap_or_else(|| "nanosplus".to_string());

    let device_type = match device_model_env.as_str() {
        "nanos" => Device::NanoS,
        "nanosplus" | "nanosp" => Device::NanoSPlus,
        "nanox" => Device::NanoX,
        "stax" => Device::Stax,
        "flex" => Device::Flex,
        "apex_p" => Device::NanoGen5,
        _ => panic!("Unknown ledger device model in env: {}", device_model_env),
    };

    let handle = Handle::new(addr, device_type);

    let mut device = create_device_connection().await;

    wait_for_valid_reponse(&mut device).await;

    let device = Arc::new(Mutex::new(device));

    let (control_msg_tx, control_msg_rx) = mpsc::channel(1);
    let auto_confirmer_handle = if should_auto_confirm() {
        Some(tokio::spawn(auto_confirmer(control_msg_rx, handle)))
    } else {
        None
    };

    (
        auto_confirmer_handle,
        control_msg_tx,
        move |chain_config, _| {
            let aux_provider: Box<dyn SigAuxDataProvider + Send> = if deterministic_signing {
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
        },
    )
}

#[rstest]
#[trace]
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_app_name() {
    let mut device = create_device_connection().await;

    wait_for_valid_reponse(&mut device).await;

    let info = device.app_info(Duration::from_millis(500)).await.unwrap();

    let version = check_current_app(&mut device).await.unwrap();
    assert_eq!(version, "0.1.0");
    assert_eq!(version, info.version);
}

#[rstest]
#[trace]
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_account_extended_public_key() {
    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(false).await;

    let signer = make_ledger_signer(Arc::new(create_mainnet()), U31::ZERO);

    let derivation_path = DerivationPath::from_str("m/44h/19788h/0h").unwrap();
    let (public_key, chain_code) = get_extended_public_key(
        &mut *signer.client.lock().await,
        CoinType::Mainnet,
        derivation_path,
    )
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

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest_reuse::apply(sign_message_test_params)]
#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message(#[case] seed: Seed, message_to_sign: MessageToSign) {
    log::debug!("test_sign_message, seed = {seed:?}");

    let mut rng = make_seedable_rng(seed);

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(false).await;

    test_sign_message_generic(
        &mut rng,
        message_to_sign,
        make_ledger_signer,
        no_another_signer(),
    )
    .await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent(#[case] seed: Seed) {
    log::debug!("test_sign_transaction_intent, seed = {seed:?}");

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(false).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(&mut rng, make_ledger_signer, no_another_signer()).await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_sign_transaction, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(false).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_ledger_signer,
        no_another_signer(),
        false,
    )
    .await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message_sig_consistency(#[case] seed: Seed) {
    log::debug!("test_sign_message_sig_consistency, seed = {seed:?}");

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_message_generic(
        &mut rng,
        MessageToSign::Random,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
    )
    .await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent_sig_consistency(#[case] seed: Seed) {
    log::debug!("test_sign_transaction_intent_sig_consistency, seed = {seed:?}");

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(
        &mut rng,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
    )
    .await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[serial_test::serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_sig_consistency(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_sign_transaction_sig_consistency, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let (auto_confirmer_handle, control_msg_tx, make_ledger_signer) = setup(true).await;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_ledger_signer,
        Some(make_deterministic_software_signer),
        false,
    )
    .await;

    if let Some(auto_confirmer_handle) = auto_confirmer_handle {
        control_msg_tx.send(ControlMessage::Finish).await.unwrap();
        auto_confirmer_handle.await.unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_fixed_signatures_no_legacy(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic_no_legacy(&mut rng, make_deterministic_software_signer).await;
}

async fn create_device_connection() -> TcpDevice {
    let mut transport = TcpTransport::new().unwrap();
    transport
        .connect(TcpInfo {
            addr: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                emulator_apdu_port(),
            ),
        })
        .await
        .unwrap()
}
