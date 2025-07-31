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
use common::{
    chain::{self},
    primitives,
};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{
        chain_code::{ChainCode, CHAINCODE_LENGTH},
        derivation_path::DerivationPath,
    },
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
};
use serialization::{Decode, DecodeAll, Encode};
use utils::ensure;
use wallet_types::hw_data::LedgerFullInfo;

use ledger_lib::Exchange;
use mintlayer_ledger_messages::{
    decode_all as ledger_decode_all, encode as ledger_encode, AddrType, Amount as LAmount,
    Bip32Path as LedgerBip32Path, CoinType, InputAdditionalInfoReq, Ins,
    OutputValue as LOutputValue, P1SignTx, PubKeyP1, PublicKeyReq, SignMessageReq, SignTxReq,
    TxInput as LTxInput, TxInputReq, TxMetadataReq, TxOutput as LTxOutput, TxOutputReq, APDU_CLASS,
    H256 as LH256, P1_APP_NAME, P1_GET_VERSION, P1_SIGN_NEXT, P1_SIGN_START, P2_DONE, P2_SIGN_MORE,
};

const MAX_ADPU_LEN: usize = (u8::MAX - 5) as usize; // 4 bytes for the header + 1 for len
const TIMEOUT_DUR: Duration = Duration::from_secs(100);
const OK_RESPONSE: u16 = 0x9000;
const TX_VERSION: u8 = 1;

#[derive(Decode)]
pub struct LedgerSignature {
    pub signature: [u8; 64],
    pub multisig_idx: Option<u32>,
}

struct SignatureResult {
    sig: LedgerSignature,
    input_idx: usize,
    has_more_signatures: bool,
}

/// Check that the response ends with the OK status code and return the rest of the response back
pub fn ok_response(mut resp: Vec<u8>) -> SignerResult<Vec<u8>> {
    let (_, status_code) = resp.split_last_chunk().ok_or(LedgerError::InvalidResponse)?;
    let response_status = u16::from_be_bytes(*status_code);

    ensure!(
        response_status == OK_RESPONSE,
        LedgerError::ErrorResponse(response_status)
    );

    resp.truncate(resp.len() - size_of_val(&response_status));
    Ok(resp)
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

/// Send a message in chunks to the ledger as the max size of a message can be 255 bytes
async fn send_chunked<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    p1: u8,
    message: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let mut msg_buf = vec![];
    let mut chunks = message.chunks(MAX_ADPU_LEN).peekable();
    let mut resp = vec![];
    while let Some(chunk) = chunks.next() {
        msg_buf.clear();

        let p2 = if chunks.peek().is_some() {
            P2_SIGN_MORE
        } else {
            P2_DONE
        };

        msg_buf.extend([APDU_CLASS, ins, p1, p2]);
        msg_buf.push(chunk.len() as u8);
        msg_buf.extend(chunk);
        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(resp)
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

    send_chunked(ledger, Ins::SIGN_MSG, P1_SIGN_START, &ledger_encode(req)).await?;

    let resp = send_chunked(ledger, Ins::SIGN_MSG, P1_SIGN_NEXT, message).await?;

    let sig_len = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let sig = resp.as_slice().get(1..1 + sig_len).ok_or(LedgerError::InvalidResponse)?;

    Ok(sig.to_vec())
}

pub async fn get_app_name<L: Exchange>(ledger: &mut L) -> Result<Vec<u8>, ledger_lib::Error> {
    let msg_buf = [APDU_CLASS, Ins::APP_NAME, P1_APP_NAME, P2_DONE];
    ledger.exchange(&msg_buf, Duration::from_millis(500)).await
}

async fn get_app_version<L: Exchange>(ledger: &mut L) -> Result<Vec<u8>, ledger_lib::Error> {
    let msg_buf = [APDU_CLASS, Ins::GET_VERSION, P1_GET_VERSION, P2_DONE];
    ledger.exchange(&msg_buf, Duration::from_millis(500)).await
}

pub async fn check_current_app<L: Exchange>(ledger: &mut L) -> SignerResult<LedgerFullInfo> {
    let resp = get_app_name(ledger)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    let resp = ok_response(resp)?;
    let name = String::from_utf8(resp).map_err(|_| LedgerError::InvalidResponse)?;

    ensure!(
        name == "mintlayer-app",
        LedgerError::DifferentActiveApp(name)
    );

    let resp = get_app_version(ledger)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    let ver = ok_response(resp)?;
    let app_version = match ver.as_slice() {
        [major, minor, patch] => common::primitives::semver::SemVer {
            major: *major,
            minor: *minor,
            patch: *patch as u16,
        },
        _ => return Err(SignerError::LedgerError(LedgerError::InvalidResponse)),
    };

    Ok(LedgerFullInfo { app_version })
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

    let pk_len = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let public_key = resp.as_slice().get(1..1 + pk_len).ok_or(LedgerError::InvalidResponse)?;
    let chain_code_len = *resp.get(1 + pk_len).ok_or(LedgerError::InvalidResponse)? as usize;
    let chain_code: [_; CHAINCODE_LENGTH] = resp
        .as_slice()
        .get(2 + pk_len..2 + pk_len + chain_code_len)
        .ok_or(LedgerError::InvalidResponse)?
        .try_into()
        .map_err(|_| LedgerError::InvalidKey)?;

    let extended_public_key = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        ChainCode::from(chain_code),
        Secp256k1PublicKey::from_bytes(public_key).map_err(|_| LedgerError::InvalidKey)?,
    );

    Ok(ExtendedPublicKey::new(extended_public_key))
}

pub async fn sign_tx<L: Exchange>(
    ledger: &mut L,
    chain_type: CoinType,
    inputs: Vec<TxInputReq>,
    input_additional_infos: Vec<InputAdditionalInfoReq>,
    outputs: Vec<TxOutputReq>,
) -> SignerResult<BTreeMap<usize, Vec<LedgerSignature>>> {
    let metadata = ledger_encode(TxMetadataReq {
        coin: chain_type,
        version: TX_VERSION,
        num_inputs: inputs.len() as u32,
        num_outputs: outputs.len() as u32,
    });
    send_chunked(ledger, Ins::SIGN_TX, P1SignTx::Metadata.into(), &metadata).await?;

    for inp in inputs {
        send_chunked(
            ledger,
            Ins::SIGN_TX,
            P1SignTx::Input.into(),
            &ledger_encode(SignTxReq::Input(inp)),
        )
        .await?;
    }

    for info in input_additional_infos {
        send_chunked(
            ledger,
            Ins::SIGN_TX,
            P1SignTx::InputAdditionalInfo.into(),
            &ledger_encode(SignTxReq::InputAdditionalInfo(info)),
        )
        .await?;
    }

    // the response from the last output will have the first signature returned
    let mut resp = vec![];
    for o in outputs {
        resp = send_chunked(
            ledger,
            Ins::SIGN_TX,
            P1SignTx::Output.into(),
            &ledger_encode(SignTxReq::Output(o)),
        )
        .await?;
    }

    let mut signatures: BTreeMap<_, Vec<_>> = BTreeMap::new();

    let next_sig = ledger_encode(SignTxReq::NextSignature);
    let mut msg_buf = vec![APDU_CLASS, Ins::SIGN_TX, P1SignTx::NextSignature.into(), P2_DONE];
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
    let has_more_signatures = *resp.last().ok_or(LedgerError::InvalidResponse)? == P2_SIGN_MORE;

    let sig = LedgerSignature::decode_all(&mut &resp[..resp.len() - 1][1..])
        .map_err(|_| LedgerError::InvalidResponse)?;

    Ok(SignatureResult {
        sig,
        input_idx,
        has_more_signatures,
    })
}

pub fn to_ledger_tx_output(value: &chain::TxOutput) -> LTxOutput {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_tx_input(value: &chain::TxInput) -> LTxInput {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_amount(value: &primitives::Amount) -> LAmount {
    LAmount::from_atoms(value.into_atoms())
}

pub fn to_ledger_output_value(value: &chain::output_value::OutputValue) -> LOutputValue {
    match value {
        chain::output_value::OutputValue::Coin(amount) => {
            LOutputValue::Coin(to_ledger_amount(amount))
        }
        chain::output_value::OutputValue::TokenV0(_) => panic!("unsupported V0"),
        chain::output_value::OutputValue::TokenV1(token_id, amount) => {
            LOutputValue::TokenV1(LH256(token_id.to_hash().into()), to_ledger_amount(amount))
        }
    }
}
