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
    hdkd::{chain_code::ChainCode, derivation_path::DerivationPath},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
};
use serialization::Encode;
use utils::ensure;

use ledger_lib::{Device, Exchange};
use ledger_proto::StatusCode;
use mintlayer_ledger_messages::{
    decode_all as ledger_decode_all, encode as ledger_encode, AccountCommand as LAccountCommand,
    AccountNonce as LAccountNonce, AccountOutPoint as LAccountOutPoint, AdditionalOrderInfo,
    AddrType, Amount as LAmount, Apdu, Bip32Path as LedgerBip32Path, CoinType,
    GetPublicKeyRespones, Id as LId, Ins, MsgSignature,
    OrderAccountCommand as LOrderAccountCommand, OutputValue as LOutputValue, P1SignTx, PubKeyP1,
    PublicKeyReq, SighashInputCommitment as LSighashInputCommitment, SignMessageReq, SignTxReq,
    Signature as LedgerSignature, TxInputReq, TxMetadataReq, TxOutput as LTxOutput, TxOutputReq,
    UtxoOutPoint as LUtxoOutPoint, APDU_CLASS, H256 as LH256, P1_SIGN_NEXT, P1_SIGN_START, P2_DONE,
    P2_MORE,
};
use wallet_types::partially_signed_transaction::OrderAdditionalInfo;

const TIMEOUT_DUR: Duration = Duration::from_secs(100);
const TX_VERSION: u8 = 1;

struct SignatureResult {
    sig: LedgerSignature,
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

/// Send a message in chunks to the ledger as the max size of a message can be 255 bytes
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
        P1_SIGN_START,
        &ledger_encode(req),
    )
    .await?;

    let resp = send_chunked(ledger, Ins::SIGN_MSG, P1_SIGN_NEXT, message).await?;

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
    input_commitments: Vec<LSighashInputCommitment>,
    outputs: Vec<TxOutputReq>,
) -> SignerResult<BTreeMap<usize, Vec<LedgerSignature>>> {
    let metadata = ledger_encode(TxMetadataReq {
        coin: chain_type,
        version: TX_VERSION,
        num_inputs: inputs.len() as u32,
        num_outputs: outputs.len() as u32,
    });
    send_chunked_expect_empty_ok_response(
        ledger,
        Ins::SIGN_TX,
        P1SignTx::Metadata.into(),
        &metadata,
    )
    .await?;

    for inp in inputs {
        send_chunked_expect_empty_ok_response(
            ledger,
            Ins::SIGN_TX,
            P1SignTx::Input.into(),
            &ledger_encode(SignTxReq::Input(inp)),
        )
        .await?;
    }

    for commitment in input_commitments {
        send_chunked_expect_empty_ok_response(
            ledger,
            Ins::SIGN_TX,
            P1SignTx::InputCommitment.into(),
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
                P1SignTx::Output.into(),
                &ledger_encode(SignTxReq::Output(o)),
            )
            .await?;
        } else {
            // the response from the last output will have the first signature returned
            resp = send_chunked(
                ledger,
                Ins::SIGN_TX,
                P1SignTx::Output.into(),
                &ledger_encode(SignTxReq::Output(o)),
            )
            .await?;
        }
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
    let has_more_signatures = *resp.last().ok_or(LedgerError::InvalidResponse)? == P2_MORE;

    let sig: LedgerSignature =
        ledger_decode_all(&resp[..resp.len() - 1][1..]).ok_or(LedgerError::InvalidResponse)?;

    Ok(SignatureResult {
        sig,
        input_idx,
        has_more_signatures,
    })
}

pub fn to_ledger_tx_output(value: &chain::TxOutput) -> LTxOutput {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_amount(value: &primitives::Amount) -> LAmount {
    LAmount::from_atoms(value.into_atoms())
}

pub fn to_ledger_outpoint(value: &chain::UtxoOutPoint) -> LUtxoOutPoint {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_account_outpoint(value: &chain::AccountOutPoint) -> LAccountOutPoint {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_account_nonce(value: &chain::AccountNonce) -> LAccountNonce {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_account_command(value: &chain::AccountCommand) -> LAccountCommand {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_order_account_command(value: &chain::OrderAccountCommand) -> LOrderAccountCommand {
    ledger_decode_all(value.encode().as_slice()).expect("ok")
}

pub fn to_ledger_additional_order_info(
    info: &OrderAdditionalInfo,
) -> SignerResult<AdditionalOrderInfo> {
    Ok(AdditionalOrderInfo {
        initially_asked: to_ledger_output_value(&info.initially_asked)?,
        initially_given: to_ledger_output_value(&info.initially_given)?,
        ask_balance: to_ledger_amount(&info.ask_balance),
        give_balance: to_ledger_amount(&info.give_balance),
    })
}

pub fn to_ledger_output_value(
    value: &chain::output_value::OutputValue,
) -> SignerResult<LOutputValue> {
    match value {
        chain::output_value::OutputValue::Coin(amount) => {
            Ok(LOutputValue::Coin(to_ledger_amount(amount)))
        }
        chain::output_value::OutputValue::TokenV0(_) => Err(SignerError::UnsupportedTokensV0),
        chain::output_value::OutputValue::TokenV1(token_id, amount) => Ok(LOutputValue::TokenV1(
            LId::new(LH256(token_id.to_hash().into())),
            to_ledger_amount(amount),
        )),
    }
}
