use std::collections::BTreeMap;

use bitcoin::secp256k1;
use protobuf::MessageField;

use super::Trezor;
use crate::{
    error::Result,
    protos::{
        self, mintlayer_tx_ack_output::MintlayerTxAckOutputWrapper,
        mintlayer_tx_ack_utxo_input::MintlayerTxAckInputWrapper,
        mintlayer_tx_request::MintlayerRequestType, MintlayerTransferTxOutput,
        MintlayerTxAckOutput, MintlayerTxAckUtxoInput, MintlayerUtxoTxInput,
    },
    Error, TrezorResponse,
};

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
// impl_array_newtype!(ChainCode, u8, 32);
// impl_bytes_newtype!(ChainCode, 32);

pub struct XPub {
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}

impl Trezor {
    // Mintlayer
    pub fn mintlayer_get_public_key(
        &mut self,
        path: Vec<u32>,
    ) -> Result<TrezorResponse<'_, XPub, protos::MintlayerPublicKey>> {
        let mut req = protos::MintlayerGetPublicKey::new();
        req.address_n = path;
        self.call(
            req,
            Box::new(|_, m| {
                Ok(XPub {
                    public_key: secp256k1::PublicKey::from_slice(m.public_key())?,
                    chain_code: ChainCode(
                        m.chain_code().try_into().map_err(|_| Error::InvalidChaincodeFromDevice)?,
                    ),
                })
            }),
        )
    }

    pub fn mintlayer_sign_tx(
        &mut self,
        inputs: Vec<MintlayerUtxoTxInput>,
        outputs: Vec<MintlayerTransferTxOutput>,
        utxos: BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTransferTxOutput>>,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let mut req = protos::MintlayerSignTx::new();
        req.set_version(1);
        req.set_inputs_count(inputs.len() as u32);
        req.set_outputs_count(outputs.len() as u32);

        eprintln!("sending tx request");
        let mut msg = self.call::<_, _, protos::MintlayerTxRequest>(req, Box::new(|_, m| Ok(m)))?;
        let mut should_ack_button = 0;
        loop {
            if should_ack_button > 0 {
                eprintln!("waiting for button to sending button ack");
                msg = msg.button_request()?.ack()?;
                should_ack_button -= 1;
                continue;
            }

            eprintln!("waiting for ok msg");
            let response = msg.ok()?;
            match response.request_type() {
                MintlayerRequestType::TXINPUT => {
                    let mut req = MintlayerTxAckInputWrapper::new();
                    req.input = MessageField::from_option(
                        inputs.get(response.details.request_index() as usize).cloned(),
                    );
                    let mut req2 = MintlayerTxAckUtxoInput::new();
                    req2.tx = MessageField::some(req);
                    eprintln!("sending tx input ack {req2:?}");
                    msg = self
                        .call::<_, _, protos::MintlayerTxRequest>(req2, Box::new(|_, m| Ok(m)))?;
                }
                MintlayerRequestType::TXOUTPUT => {
                    let mut req = MintlayerTxAckOutputWrapper::new();
                    if response.details.has_tx_hash() {
                        let tx_id: [u8; 32] = response
                            .details
                            .tx_hash()
                            .try_into()
                            .map_err(|_| Error::InvalidChaincodeFromDevice)?;
                        let out = utxos
                            .get(&tx_id)
                            .and_then(|tx| tx.get(&response.details.request_index()));
                        req.output = MessageField::from_option(out.cloned());
                        eprintln!("sending tx input output utxo");
                    } else {
                        req.output = MessageField::from_option(
                            outputs.get(response.details.request_index() as usize).cloned(),
                        );
                        eprintln!("sending tx output");
                        should_ack_button += 2;
                        if response.details.request_index() as usize == outputs.len() - 1 {
                            eprintln!("last output will wait for one more ack");
                            should_ack_button += 1;
                        }
                    }
                    let mut req2 = MintlayerTxAckOutput::new();
                    req2.tx = MessageField::some(req);
                    msg = self
                        .call::<_, _, protos::MintlayerTxRequest>(req2, Box::new(|_, m| Ok(m)))?;
                }
                MintlayerRequestType::TXMETA => {
                    return Err(Error::MalformedMintlayerTxRequest(response))
                }
                MintlayerRequestType::TXFINISHED => {
                    return Ok(response
                        .serialized
                        .iter()
                        .map(|s| Some(s.signature().to_vec()))
                        .collect())
                }
            }
        }
    }
}
