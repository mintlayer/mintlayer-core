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

use ledger_lib::{Device, Exchange};
use mintlayer_ledger_messages as ledger_msg;

use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivation_path::DerivationPath},
    secp256k1::{Secp256k1PublicKey, extended_keys::Secp256k1ExtendedPublicKey},
};
use utils::ensure;

use crate::signer::ledger_signer::{LedgerError, SHORT_TIMEOUT_DUR, TIMEOUT_DUR};

use super::LedgerSignature;

macro_rules! ensure_response_type {
    ($resp:expr, $pattern:pat $(if $guard:expr)?, $out:expr) => {
        {
            let to_match = $resp;
            match to_match {
                $pattern $(if $guard)? => $out,
                _ => {
                    return Err(LedgerError::WrongResponse);
                }
            }
        }
    };
}

/// Check that the response ends with the OK status code and return the rest of the response back
fn extract_response_apdu_data(mut resp: Vec<u8>) -> Result<Vec<u8>, LedgerError> {
    let (_, status_code) = resp.split_last_chunk().ok_or(LedgerError::InvalidResponseApdu)?;
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
    exchange_message_with_timeout(ledger, msg_buf, TIMEOUT_DUR).await
}

async fn exchange_message_with_timeout<L: Exchange>(
    ledger: &mut L,
    msg_buf: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, LedgerError> {
    let resp = ledger.exchange(msg_buf, timeout).await?;
    extract_response_apdu_data(resp)
}

fn decode_response(resp_data: &[u8]) -> Result<ledger_msg::Response, LedgerError> {
    ledger_msg::decode_all(resp_data).ok_or(LedgerError::CannotDecodeResponse)
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
            let resp = decode_response(&resp)?;
            ensure_response_type!(resp, ledger_msg::Response::ExpectingNextChunk, ());
        }
    }

    Ok(resp)
}

fn make_apdu<'a>(
    instruction_byte: u8,
    param1_byte: u8,
    command_data: &'a [u8],
) -> Result<ledger_msg::Apdu<'a>, LedgerError> {
    ledger_msg::Apdu::new_with_data(instruction_byte, param1_byte, command_data)
        .ok_or(LedgerError::ApduMessageTooLong)
}

pub async fn sign_challenge<L: Exchange>(
    ledger: &mut L,
    coin_type: ledger_msg::CoinType,
    path: ledger_msg::Bip32Path,
    addr_type: ledger_msg::AddrType,
    message: &[u8],
) -> Result<ledger_msg::Signature, LedgerError> {
    let req = ledger_msg::SignMessageStartReq {
        coin_type,
        addr_type,
        path,
    };

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::SIGN_MSG,
        ledger_msg::SignMsgP1::Start.into(),
        &ledger_msg::encode(&req),
    )
    .await?;
    let resp = decode_response(&resp)?;
    ensure_response_type!(resp, ledger_msg::Response::MessageSetup, ());

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::SIGN_MSG,
        ledger_msg::SignMsgP1::Next.into(),
        message,
    )
    .await?;

    let resp = decode_response(&resp)?;
    let resp = ensure_response_type!(resp, ledger_msg::Response::MessageSignature(resp), resp);

    Ok(resp.signature)
}

pub fn check_current_app_info(info: ledger_lib::info::AppInfo) -> Result<String, LedgerError> {
    ensure!(
        info.name == "Mintlayer",
        LedgerError::DifferentActiveApp(info.name)
    );
    Ok(info.version)
}

#[allow(unused)]
pub async fn check_current_app<L: Exchange + Device + Send>(
    ledger: &mut L,
) -> Result<String, LedgerError> {
    let info = ledger.app_info(TIMEOUT_DUR).await?;
    check_current_app_info(info)
}

pub async fn ping<L: Exchange>(ledger: &mut L) -> Result<(), LedgerError> {
    let apdu = make_apdu(ledger_msg::Ins::PING, ledger_msg::PingP1::Dummy.into(), &[])?;

    let mut msg_buf = Vec::with_capacity(apdu.bytes_count());
    apdu.write_bytes(&mut msg_buf);

    let resp = exchange_message_with_timeout(ledger, &msg_buf, SHORT_TIMEOUT_DUR).await?;
    let resp = decode_response(&resp)?;
    ensure_response_type!(resp, ledger_msg::Response::Pong, ());

    Ok(())
}

pub async fn get_extended_public_key<L: Exchange>(
    ledger: &mut L,
    coin_type: ledger_msg::CoinType,
    derivation_path: DerivationPath,
) -> Result<ExtendedPublicKey, LedgerError> {
    let path = ledger_msg::Bip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );
    let req = ledger_msg::GetPubKeyReq { coin_type, path };

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::GET_PUB_KEY,
        ledger_msg::GetPubKeyP1::NoDisplayAddress.into(),
        &ledger_msg::encode(&req),
    )
    .await?;

    let resp = decode_response(&resp)?;
    let resp = ensure_response_type!(resp, ledger_msg::Response::PublicKey(resp), resp);

    let extended_public_key = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        ChainCode::from(resp.chain_code.0),
        Secp256k1PublicKey::from_bytes(&resp.public_key.0).map_err(|_| LedgerError::InvalidKey)?,
    );

    Ok(ExtendedPublicKey::new(extended_public_key))
}

pub async fn sign_tx<L: Exchange>(
    ledger: &mut L,
    coin_type: ledger_msg::CoinType,
    inputs: Vec<ledger_msg::TxInputData>,
    input_commitments: Vec<ledger_msg::SighashInputCommitment>,
    outputs: Vec<ledger_msg::TxOutputData>,
) -> Result<BTreeMap<usize, Vec<LedgerSignature>>, LedgerError> {
    let start_req = ledger_msg::encode(&ledger_msg::SignTxStartReq {
        coin_type,
        version: ledger_msg::TransactionVersion::V1,
        num_inputs: inputs.len() as u32,
        num_outputs: outputs.len() as u32,
    });

    let resp = send_chunked(
        ledger,
        ledger_msg::Ins::SIGN_TX,
        ledger_msg::SignTxP1::Start.into(),
        &start_req,
    )
    .await?;
    let resp = decode_response(&resp)?;
    ensure_response_type!(resp, ledger_msg::Response::TxSetup, ());

    for input in inputs {
        let resp = send_chunked(
            ledger,
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignTxP1::Next.into(),
            &ledger_msg::encode(&ledger_msg::SignTxNextReq::ProcessInput(Box::new(input))),
        )
        .await?;
        let resp = decode_response(&resp)?;
        ensure_response_type!(resp, ledger_msg::Response::TxNext, ());
    }

    for commitment in input_commitments {
        let resp = send_chunked(
            ledger,
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignTxP1::Next.into(),
            &ledger_msg::encode(&ledger_msg::SignTxNextReq::ProcessInputCommitment(
                Box::new(ledger_msg::TxInputCommitmentData { commitment }),
            )),
        )
        .await?;
        let resp = decode_response(&resp)?;
        ensure_response_type!(resp, ledger_msg::Response::TxNext, ());
    }

    for output in outputs {
        let resp = send_chunked(
            ledger,
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignTxP1::Next.into(),
            &ledger_msg::encode(&ledger_msg::SignTxNextReq::ProcessOutput(Box::new(output))),
        )
        .await?;

        let resp = decode_response(&resp)?;
        ensure_response_type!(resp, ledger_msg::Response::TxNext, ());
    }

    let next_sig_raw_req = {
        let next_sig = ledger_msg::encode(&ledger_msg::SignTxNextReq::ReturnNextSignature);
        let apdu = make_apdu(
            ledger_msg::Ins::SIGN_TX,
            ledger_msg::SignTxP1::Next.into(),
            &next_sig,
        )?;

        let mut msg_buf = Vec::with_capacity(apdu.bytes_count());
        apdu.write_bytes(&mut msg_buf);
        msg_buf
    };

    let mut signatures: BTreeMap<_, Vec<_>> = BTreeMap::new();

    loop {
        let sig_resp = exchange_message(ledger, &next_sig_raw_req).await?;

        let resp = decode_response(&sig_resp)?;
        let resp = ensure_response_type!(resp, ledger_msg::Response::TxInputSignature(resp), resp);

        signatures.entry(resp.input_idx as usize).or_default().push(LedgerSignature {
            signature: resp.signature,
            multisig_idx: resp.multisig_idx,
        });

        if !resp.has_next {
            break;
        }
    }

    Ok(signatures)
}
