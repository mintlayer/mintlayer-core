// Copyright (c) 2021 RBB S.r.l
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
//
// Author(s): S. Afach

use generic_array::{ArrayLength, GenericArray};
use merlin::Transcript;
use schnorrkel::{
    vrf::{VRFInOut, VRFPreOut, VRFProof},
    PublicKey,
};
use serialization::{Decode, Encode};

use crate::vrf::{VRFError, VRFPublicKey};

const VRF_OUTPUT_LABEL: &[u8] = b"MintlayerVRFOutput!";

const SCHNORKEL_PREOUT_SIZE: usize = 32;
const SCHNORKEL_PROOF_SIZE: usize = 64;
const SCHNORKEL_RETURN_SIZE: usize = SCHNORKEL_PREOUT_SIZE + SCHNORKEL_PROOF_SIZE;

#[must_use]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrkelVRFReturn {
    /// preout is the incomplete version of the output of the VRF
    /// later, it has to be attached to the input so that it can
    /// form a complete output
    preout: VRFPreOut,
    proof: VRFProof,
}

impl Encode for SchnorrkelVRFReturn {
    fn size_hint(&self) -> usize {
        SCHNORKEL_RETURN_SIZE
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.preout.to_bytes());
        dest.write(&self.proof.to_bytes());
    }

    fn encoded_size(&self) -> usize {
        SCHNORKEL_RETURN_SIZE
    }
}

impl Decode for SchnorrkelVRFReturn {
    fn encoded_fixed_size() -> Option<usize> {
        Some(SCHNORKEL_RETURN_SIZE)
    }

    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        const PREOUT_ERR_MSG: &str = "Failed to read schnorrkel preout data";
        const PROOF_ERR_MSG: &str = "Failed to read schnorrkel proof data";
        let preout = {
            let mut v = [0; SCHNORKEL_PREOUT_SIZE];
            input.read(v.as_mut_slice())?;
            VRFPreOut::from_bytes(&v).map_err(|_| serialization::Error::from(PREOUT_ERR_MSG))?
        };
        let proof = {
            let mut v = [0; SCHNORKEL_PROOF_SIZE];
            input.read(v.as_mut_slice())?;
            VRFProof::from_bytes(&v).map_err(|_| serialization::Error::from(PROOF_ERR_MSG))?
        };
        Ok(Self { preout, proof })
    }
}

impl SchnorrkelVRFReturn {
    pub(super) fn new(preout: VRFPreOut, proof: VRFProof) -> Self {
        Self { preout, proof }
    }

    pub(super) fn proof(&self) -> &VRFProof {
        &self.proof
    }

    pub(super) fn preout(&self) -> &VRFPreOut {
        &self.preout
    }

    pub fn vrf_preout(&self) -> [u8; 32] {
        self.preout.to_bytes()
    }

    pub fn vrf_proof(&self) -> [u8; 64] {
        self.proof.to_bytes()
    }

    /// to create the output, we need the input as well as per Ouroborous Praos Theorem 2 (information taken from Schnorrkel repo)
    /// Hence, we use this step to restore VRFInOut from the transcript + preout + public key
    ///
    /// We commit both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendix C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    fn attach_input_to_output(
        &self,
        public_key: PublicKey,
        transcript: Transcript,
    ) -> Result<VRFInOut, VRFError> {
        self.preout
            .attach_input_hash(&public_key, transcript)
            .map_err(|e| VRFError::InputAttachError(e.to_string()))
    }

    pub fn calculate_vrf_output<OutputSize: ArrayLength<u8>>(
        &self,
        public_key: PublicKey,
        transcript: Transcript,
    ) -> Result<GenericArray<u8, OutputSize>, VRFError> {
        let input_and_output = self.attach_input_to_output(public_key, transcript)?;
        let result = input_and_output.make_bytes::<GenericArray<u8, OutputSize>>(VRF_OUTPUT_LABEL);
        Ok(result)
    }

    pub fn calculate_vrf_output_with_generic_key<OutputSize: ArrayLength<u8>>(
        &self,
        public_key: VRFPublicKey,
        transcript: Transcript,
    ) -> Result<GenericArray<u8, OutputSize>, VRFError> {
        match public_key.pub_key {
            crate::vrf::VRFPublicKeyHolder::Schnorrkel(pub_key) => {
                self.calculate_vrf_output(pub_key.key, transcript)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::Rng;
    use crate::random::{make_pseudo_rng, make_true_rng};
    use hex::FromHex;
    use schnorrkel::{signing_context, Keypair, PublicKey, SecretKey};
    use serialization::{DecodeAll, Encode};

    #[test]
    fn serialization_of_result() {
        let mut csprng = make_true_rng();
        let keypair = Keypair::generate_with(&mut csprng);

        let mut rng = make_pseudo_rng();

        let label_size = 1 + rng.gen::<usize>() % 10000;
        let label: Vec<u8> = (1..label_size).map(|_| rand::random::<u8>()).collect();

        let ctx = signing_context(&label);
        let msg_size = 1 + rng.gen::<usize>() % 10000;
        let msg: Vec<u8> = (1..msg_size).map(|_| rand::random::<u8>()).collect();
        let (input_and_output, proof, _proof1batchable) = keypair.vrf_sign(ctx.bytes(&msg));
        let preout = &input_and_output.to_preout();

        let vrf_out = SchnorrkelVRFReturn::new(*preout, proof.clone());
        let vrf_out_encoded = vrf_out.encode();

        assert_eq!(vrf_out_encoded.len(), SCHNORKEL_RETURN_SIZE);

        let vrf_out_decoded =
            SchnorrkelVRFReturn::decode_all(&mut vrf_out_encoded.as_slice()).unwrap();

        assert_eq!(vrf_out_decoded.preout(), preout);
        assert_eq!(*vrf_out_decoded.proof(), proof);

        keypair
            .public
            .vrf_verify(
                ctx.bytes(&msg),
                vrf_out_decoded.preout(),
                vrf_out_decoded.proof(),
            )
            .expect("Correct VRF verification failed");
    }

    #[test]
    fn serialization_of_result_with_select_values() {
        let secret_key_encoded: Vec<u8> = FromHex::from_hex("f20c127c94ef4db265b5e8a49d2621f9d6afa45f63b727d9e9eaa7efa2b02f0d8d292c85b0ca8a673cc0da855b401ecbb358a4b15592de2f9ba73cb229a1763f").unwrap();
        let public_key_encoded: Vec<u8> =
            FromHex::from_hex("a2cca95ad511eb1d0476938185519be718066cb083e351a1c3fe1806a4901627")
                .unwrap();
        assert_eq!(secret_key_encoded.len(), 64);
        assert_eq!(public_key_encoded.len(), 32);
        let secret_key = SecretKey::from_bytes(&secret_key_encoded).unwrap();
        let public_key = PublicKey::from_bytes(&public_key_encoded).unwrap();
        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };

        let label: Vec<u8> = FromHex::from_hex("b1d98117b0db617adbb95f2a7ac6c2ffd9c00972ce15a41ecd7ef629ab8082db74f7243da9a618e909a06c265185513dbc60f70d5dc7b8b1212af7718388d0adc944b7a20a4f939b2df418dacb21cfee2c3aa602e34384f729d05e88313b821f50754cb4b9946ddfe3dba6c728c842138e1ecf5fe69214bb73d2d2db42f0c82000749d619b2ac7302c35779d06729fcaa10d51f8992a78c547272351ef0d3f6b58837331c6d3d31612519bdee3f2774a37c3c5be47e0").unwrap();

        let ctx = signing_context(&label);
        let msg: Vec<u8> = FromHex::from_hex("17ce26cab219571e28a08126eb302bddb35d00d139879321de621ca3c456805796f9a5edfe8903fc5b53f5e0c18b39742eb837a9f080c984fc8069e32d0e7662e3cd77d7e38b1a51860e9ed4c7b38f9d02536aeb8cb766ac4b540e77413b82ed542b798f7935650574d34d5d5fa3691867b9848a9cd5fff786e15aeae426fb2f10462aad07617973c64e440a66dc7dd180b4ddf7e015114b1df2058aaa7ad633fd9e572e4552e62c2e17c93d69d45873c025fe418a14c87d2460442ae6fb15c2e28f709e78531e489db0b28224c54e403b7bd64fcc3cb0264d77053b4cca744e9a57cc59438c1cc28a963d43647374f27b5fad813b03413902e7342957e874b8522102f65680902fc8d1a8bcbbf39a61a2f2ae5e60cca2296ea3e7b2c7d3cec249eb599867f6b117b5b2424266cf").unwrap();

        let vrf_out_encoded: Vec<u8> = FromHex::from_hex("88c59e2b40c5e3720ae8d41ab4a3d6fc1d2c86d8cac27133a9b7211411225661e02c48363c1af608d6463c37a55bc3612a8aa43b762e8f73a332abe242e4120d54b2c05a566bc4460904430d5d9f10db8204a05c9c423b4164cddce303da8900").unwrap();

        assert_eq!(vrf_out_encoded.len(), SCHNORKEL_RETURN_SIZE);

        let vrf_out_decoded =
            SchnorrkelVRFReturn::decode_all(&mut vrf_out_encoded.as_slice()).unwrap();

        keypair
            .public
            .vrf_verify(
                ctx.bytes(&msg),
                vrf_out_decoded.preout(),
                vrf_out_decoded.proof(),
            )
            .expect("Correct VRF verification failed");

        ///////////////////////////////////////
        // let's redo the signing and recheck the preout, just out of paranoia
        let (input_and_output, _proof, _proof1batchable) = keypair.vrf_sign(ctx.bytes(&msg));
        let preout = &input_and_output.to_preout();

        assert_eq!(vrf_out_decoded.preout(), preout);
        // the proof is not always the same, so, it can't be checked
        // assert_eq!(*vrf_out_decoded.proof(), proof);
    }
}
