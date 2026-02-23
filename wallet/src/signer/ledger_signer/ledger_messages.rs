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

use std::{collections::BTreeMap, mem::size_of_val, time::Duration};

use crate::signer::ledger_signer::LedgerError;
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivation_path::DerivationPath},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
};
use utils::ensure;

use ledger_lib::{Device, Exchange};
use mintlayer_ledger_messages as ledger_msg;

/// Timeout duration for normal Ledger operations
const TIMEOUT_DUR: Duration = Duration::from_secs(100);
/// While trying to get a successful operation use a short timeout.
/// Used in between normal operations when the screen is showing success/failure,
/// and the Ledger app doesn't respond with any response so no need to wait for a long time.
const SHORT_TIMEOUT_DUR: Duration = Duration::from_millis(200);
/// The supported transaction version by the ledger app
const TX_VERSION: u8 = 1;

/// Ledger Signer errors
#[derive(thiserror::Error, Debug)]
pub enum LedgerMessagesError {
    #[error("Device error: {0}")]
    DeviceError(ledger_lib::Error),
    #[error("Derivation path too long")]
    DerivationPathTooLong,
    #[error("APDU message too long")]
    ApduMessageTooLong,
}

/// Check that the response ends with the OK status code and return the rest of the response back
pub fn ok_response(mut resp: Vec<u8>) -> Result<Vec<u8>, LedgerError> {
    let (_, status_code) = resp.split_last_chunk().ok_or(LedgerError::InvalidResponse)?;
    let response_status = u16::from_be_bytes(*status_code);
    let status_word_ok: u16 = ledger_msg::StatusWord::Ok.into();

    if response_status == status_word_ok {
        resp.truncate(resp.len() - size_of_val(&response_status));
        return Ok(resp);
    }

    match ledger_msg::StatusWord::try_from(response_status) {
        Ok(word) => Err(LedgerError::ErrorResponse(word.to_string())),
        Err(_) => Err(LedgerError::ErrorResponse(format!(
            "Unknown device status code: 0x{:04X}",
            response_status
        ))),
    }
}

/// Send a message to the Ledger and check the response status code is ok
async fn exchange_message<L: Exchange>(
    ledger: &mut L,
    msg_buf: &[u8],
) -> Result<Vec<u8>, LedgerError> {
    let resp = ledger
        .exchange(msg_buf, TIMEOUT_DUR)
        .await
        .map_err(LedgerMessagesError::DeviceError)?;
    ok_response(resp)
}

/// Send a message in chunks to the ledger as the max size of a message is 255 bytes
async fn send_chunked<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    p1: u8,
    message: &[u8],
) -> Result<Vec<u8>, LedgerError> {
    let mut msg_buf = vec![];
    let chunks = ledger_msg::Apdu::new_chunks(ins, p1, message);
    let mut resp = vec![];

    for chunk in chunks {
        msg_buf.clear();
        msg_buf.reserve(chunk.bytes_count());
        chunk.write_bytes(&mut msg_buf);

        resp = exchange_message(ledger, &msg_buf).await?;
        if !chunk.is_last() {
            ensure!(resp.is_empty(), LedgerError::InvalidResponse);
        }
    }

    Ok(resp)
}

async fn send_chunked_expect_empty_ok_response<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    p1: u8,
    message: &[u8],
) -> Result<(), LedgerError> {
    let resp = send_chunked(ledger, ins, p1, message).await?;
    ensure!(resp.is_empty(), LedgerError::InvalidResponse);
    Ok(())
}

pub async fn sign_challenge<L: Exchange>(
    ledger: &mut L,
    coin: ledger_msg::CoinType,
    path: ledger_msg::Bip32Path,
    addr_type: ledger_msg::AddrType,
    message: &[u8],
) -> Result<Vec<u8>, LedgerError> {
    let req = ledger_msg::SignMessageReq {
        coin,
        addr_type,
        path,
    };

    send_chunked_expect_empty_ok_response(
        ledger,
        ledger_msg::Ins::SIGN_MSG,
        ledger_msg::SignP1::Start.into(),
        &ledger_msg::encode(req),
    )
    .await?;

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::SIGN_MSG,
        ledger_msg::SignP1::Next.into(),
        message,
    )
    .await?;

    let sig: ledger_msg::MsgSignature =
        ledger_msg::decode_all(&resp).ok_or(LedgerError::InvalidResponse)?;

    Ok(sig.signature.to_vec())
}

pub async fn check_current_app<L: Exchange + Device + Send>(
    ledger: &mut L,
) -> Result<String, LedgerError> {
    let info = ledger.app_info(TIMEOUT_DUR).await.map_err(LedgerMessagesError::DeviceError)?;
    let name = info.name;
    let app_version = info.version;

    ensure!(name == "Mintlayer", LedgerError::DifferentActiveApp(name));

    Ok(app_version)
}

pub async fn get_extended_public_key_raw<L: Exchange>(
    ledger: &mut L,
    coin_type: ledger_msg::CoinType,
    derivation_path: &DerivationPath,
) -> Result<Vec<u8>, LedgerMessagesError> {
    let path = ledger_msg::Bip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );
    let req = ledger_msg::PublicKeyReq { coin_type, path };
    let encoded_req = ledger_msg::encode(req);

    let apdu = ledger_msg::Apdu::new_with_data(
        ledger_msg::Ins::PUB_KEY,
        ledger_msg::PubKeyP1::NoDisplayAddress.into(),
        &encoded_req,
    )
    .ok_or(LedgerMessagesError::DerivationPathTooLong)?;

    let mut msg_buf = Vec::with_capacity(apdu.bytes_count());
    apdu.write_bytes(&mut msg_buf);

    ledger
        .exchange(&msg_buf, SHORT_TIMEOUT_DUR)
        .await
        .map_err(LedgerMessagesError::DeviceError)
}

pub async fn get_extended_public_key<L: Exchange>(
    ledger: &mut L,
    coin_type: ledger_msg::CoinType,
    derivation_path: DerivationPath,
) -> Result<ExtendedPublicKey, LedgerError> {
    let path = ledger_msg::Bip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );
    let req = ledger_msg::PublicKeyReq { coin_type, path };

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::PUB_KEY,
        ledger_msg::PubKeyP1::NoDisplayAddress.into(),
        &ledger_msg::encode(req),
    )
    .await?;

    let resp: ledger_msg::GetPublicKeyRespones =
        ledger_msg::decode_all(&resp).ok_or(LedgerError::InvalidResponse)?;

    let extended_public_key = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        ChainCode::from(resp.chain_code),
        Secp256k1PublicKey::from_bytes(&resp.public_key).map_err(|_| LedgerError::InvalidKey)?,
    );

    Ok(ExtendedPublicKey::new(extended_public_key))
}

pub async fn sign_tx<L: Exchange>(
    ledger: &mut L,
    chain_type: ledger_msg::CoinType,
    inputs: Vec<ledger_msg::TxInputReq>,
    input_commitments: Vec<ledger_msg::SighashInputCommitment>,
    outputs: Vec<ledger_msg::TxOutputReq>,
) -> Result<BTreeMap<usize, Vec<ledger_msg::Signature>>, LedgerError> {
    let metadata = ledger_msg::encode(ledger_msg::TxMetadataReq {
        coin: chain_type,
        version: TX_VERSION,
        num_inputs: inputs.len() as u32,
        num_outputs: outputs.len() as u32,
    });
    send_chunked_expect_empty_ok_response(
        ledger,
        ledger_msg::Ins::SIGN_TX,
        ledger_msg::SignP1::Start.into(),
        &metadata,
    )
    .await?;

    for inp in inputs {
        send_chunked_expect_empty_ok_response(
            ledger,
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignP1::Next.into(),
            &ledger_msg::encode(ledger_msg::SignTxReq::Input(inp)),
        )
        .await?;
    }

    for commitment in input_commitments {
        send_chunked_expect_empty_ok_response(
            ledger,
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignP1::Next.into(),
            &ledger_msg::encode(ledger_msg::SignTxReq::InputCommitment(commitment)),
        )
        .await?;
    }

    let mut resp = vec![];
    let num_outputs = outputs.len();
    for (idx, o) in outputs.into_iter().enumerate() {
        if idx < num_outputs - 1 {
            send_chunked_expect_empty_ok_response(
                ledger,
                ledger_msg::Ins::SIGN_TX,
                ledger_msg::SignP1::Next.into(),
                &ledger_msg::encode(ledger_msg::SignTxReq::Output(o)),
            )
            .await?;
        } else {
            // the response from the last output will have the first signature returned
            resp = send_chunked(
                ledger,
                ledger_msg::Ins::SIGN_TX,
                ledger_msg::SignP1::Next.into(),
                &ledger_msg::encode(ledger_msg::SignTxReq::Output(o)),
            )
            .await?;
        }
    }

    let mut signatures: BTreeMap<_, Vec<_>> = BTreeMap::new();

    let next_sig = ledger_msg::encode(ledger_msg::SignTxReq::NextSignature);
    let apdu = ledger_msg::Apdu::new_with_data(
        ledger_msg::Ins::SIGN_TX,
        ledger_msg::SignP1::Next.into(),
        &next_sig,
    )
    .ok_or(LedgerMessagesError::ApduMessageTooLong)?;

    let mut msg_buf = Vec::with_capacity(apdu.bytes_count());
    apdu.write_bytes(&mut msg_buf);

    loop {
        let ledger_msg::SignatureResponse {
            signature,
            input_idx,
            has_next,
        } = ledger_msg::decode_all(&resp).ok_or(LedgerError::InvalidResponse)?;

        signatures.entry(input_idx as usize).or_default().push(signature);

        if !has_next {
            break;
        }

        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(signatures)
}
