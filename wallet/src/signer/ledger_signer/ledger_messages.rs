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

use crate::signer::{ledger_signer::LedgerError, SignerError, SignerResult};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivation_path::DerivationPath},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
};
use utils::ensure;

use ledger_lib::{Device, Exchange};
use ledger_proto::StatusCode;
use mintlayer_ledger_messages::{
    decode_all as ledger_decode_all, encode as ledger_encode, AddrType, Apdu,
    Bip32Path as LedgerBip32Path, CoinType, GetPublicKeyRespones, Ins, MsgSignature, PubKeyP1,
    PublicKeyReq, SighashInputCommitment, SignMessageReq, SignP1, SignTxReq, Signature, TxInputReq,
    TxMetadataReq, TxOutputReq, APDU_CLASS, P2_DONE, P2_MORE,
};

const TIMEOUT_DUR: Duration = Duration::from_secs(100);
const TX_VERSION: u8 = 1;

struct SignatureResult {
    sig: Signature,
    input_idx: usize,
    has_more_signatures: bool,
}

/// Check that the response ends with the OK status code and return the rest of the response back
pub fn ok_response(mut resp: Vec<u8>) -> SignerResult<Vec<u8>> {
    let (_, status_code) = resp.split_last_chunk().ok_or(LedgerError::InvalidResponse)?;
    let response_status = u16::from_be_bytes(*status_code);

    let code = StatusCode::try_from(response_status)
        .map_err(|_| LedgerError::ErrorResponse(format!("Unknown error: {response_status}")))?;

    match code {
        StatusCode::Ok => {
            resp.truncate(resp.len() - size_of_val(&response_status));
            Ok(resp)
        }
        err => Err(LedgerError::ErrorResponse(err.to_string()).into()),
    }
}

/// Send a message to the Ledger and check the response status code is ok
async fn exchange_message<L: Exchange>(
    ledger: &mut L,
    msg_buf: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let resp = ledger
        .exchange(msg_buf, TIMEOUT_DUR)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    ok_response(resp)
}

/// Send a message in chunks to the ledger as the max size of a message is 255 bytes
async fn send_chunked<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    p1: u8,
    message: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let mut msg_buf = vec![];
    let chunks = Apdu::new_chunks(ins, p1, message);
    let mut resp = vec![];
    for chunk in chunks {
        msg_buf.clear();
        msg_buf.reserve(chunk.bytes_count());
        chunk.write_bytes(&mut msg_buf);

        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(resp)
}

async fn send_chunked_expect_empty_ok_response<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    p1: u8,
    message: &[u8],
) -> Result<(), SignerError> {
    let resp = send_chunked(ledger, ins, p1, message).await?;
    ensure!(resp.is_empty(), LedgerError::InvalidResponse);
    Ok(())
}

pub async fn sign_challenge<L: Exchange>(
    ledger: &mut L,
    coin: CoinType,
    path: LedgerBip32Path,
    addr_type: AddrType,
    message: &[u8],
) -> SignerResult<Vec<u8>> {
    let req = SignMessageReq {
        coin,
        addr_type,
        path,
    };

    send_chunked_expect_empty_ok_response(
        ledger,
        Ins::SIGN_MSG,
        SignP1::Start.into(),
        &ledger_encode(req),
    )
    .await?;

    let resp = send_chunked(ledger, Ins::SIGN_MSG, SignP1::Next.into(), message).await?;

    let sig: MsgSignature = ledger_decode_all(&resp).ok_or(LedgerError::InvalidResponse)?;

    Ok(sig.signature.to_vec())
}

pub async fn check_current_app<L: Exchange + Device + Send>(
    ledger: &mut L,
) -> SignerResult<String> {
    let info = ledger
        .app_info(TIMEOUT_DUR)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    let name = info.name;
    let app_version = info.version;

    ensure!(
        name == "mintlayer-app",
        LedgerError::DifferentActiveApp(name)
    );

    Ok(app_version)
}

pub async fn get_extended_public_key_raw<L: Exchange>(
    ledger: &mut L,
    coin_type: CoinType,
    derivation_path: &DerivationPath,
) -> Result<Vec<u8>, ledger_lib::Error> {
    let path = LedgerBip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );
    let req = PublicKeyReq { coin_type, path };
    let encoded_req = ledger_encode(req);

    let apdu = Apdu::new_with_data(
        Ins::PUB_KEY,
        PubKeyP1::NoDisplayAddress.into(),
        &encoded_req,
    )
    .expect("ok size");

    let mut msg_buf = Vec::with_capacity(apdu.bytes_count());
    apdu.write_bytes(&mut msg_buf);

    ledger.exchange(&msg_buf, Duration::from_millis(200)).await
}

pub async fn get_extended_public_key<L: Exchange>(
    ledger: &mut L,
    coin_type: CoinType,
    derivation_path: DerivationPath,
) -> SignerResult<ExtendedPublicKey> {
    let path = LedgerBip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );
    let req = PublicKeyReq { coin_type, path };

    let resp = send_chunked(
        ledger,
        Ins::PUB_KEY,
        PubKeyP1::NoDisplayAddress.into(),
        &ledger_encode(req),
    )
    .await?;

    let resp: GetPublicKeyRespones =
        ledger_decode_all(&resp).ok_or(LedgerError::InvalidResponse)?;

    let extended_public_key = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        ChainCode::from(resp.chain_code),
        Secp256k1PublicKey::from_bytes(&resp.public_key).map_err(|_| LedgerError::InvalidKey)?,
    );

    Ok(ExtendedPublicKey::new(extended_public_key))
}

pub async fn sign_tx<L: Exchange>(
    ledger: &mut L,
    chain_type: CoinType,
    inputs: Vec<TxInputReq>,
    input_commitments: Vec<SighashInputCommitment>,
    outputs: Vec<TxOutputReq>,
) -> SignerResult<BTreeMap<usize, Vec<Signature>>> {
    let metadata = ledger_encode(TxMetadataReq {
        coin: chain_type,
        version: TX_VERSION,
        num_inputs: inputs.len() as u32,
        num_outputs: outputs.len() as u32,
    });
    send_chunked_expect_empty_ok_response(ledger, Ins::SIGN_TX, SignP1::Start.into(), &metadata)
        .await?;

    for inp in inputs {
        send_chunked_expect_empty_ok_response(
            ledger,
            Ins::SIGN_TX,
            SignP1::Next.into(),
            &ledger_encode(SignTxReq::Input(inp)),
        )
        .await?;
    }

    for commitment in input_commitments {
        send_chunked_expect_empty_ok_response(
            ledger,
            Ins::SIGN_TX,
            SignP1::Next.into(),
            &ledger_encode(SignTxReq::InputCommitment(commitment)),
        )
        .await?;
    }

    let mut resp = vec![];
    let num_outputs = outputs.len();
    for (idx, o) in outputs.into_iter().enumerate() {
        if idx < num_outputs - 1 {
            send_chunked_expect_empty_ok_response(
                ledger,
                Ins::SIGN_TX,
                SignP1::Next.into(),
                &ledger_encode(SignTxReq::Output(o)),
            )
            .await?;
        } else {
            // the response from the last output will have the first signature returned
            resp = send_chunked(
                ledger,
                Ins::SIGN_TX,
                SignP1::Next.into(),
                &ledger_encode(SignTxReq::Output(o)),
            )
            .await?;
        }
    }

    let mut signatures: BTreeMap<_, Vec<_>> = BTreeMap::new();

    let next_sig = ledger_encode(SignTxReq::NextSignature);
    let mut msg_buf = vec![APDU_CLASS, Ins::SIGN_TX, SignP1::Next.into(), P2_DONE];
    msg_buf.push(next_sig.len() as u8);
    msg_buf.extend(next_sig);
    loop {
        let SignatureResult {
            sig,
            input_idx,
            has_more_signatures,
        } = decode_signature_response(&resp)?;

        signatures.entry(input_idx).or_default().push(sig);

        if !has_more_signatures {
            break;
        }

        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(signatures)
}

fn decode_signature_response(resp: &[u8]) -> Result<SignatureResult, LedgerError> {
    let input_idx = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let has_more_signatures = *resp.last().ok_or(LedgerError::InvalidResponse)? == P2_MORE;

    let sig =
        ledger_decode_all(&resp[..resp.len() - 1][1..]).ok_or(LedgerError::InvalidResponse)?;

    Ok(SignatureResult {
        sig,
        input_idx,
        has_more_signatures,
    })
}
