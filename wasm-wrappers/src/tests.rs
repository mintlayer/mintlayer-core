// Copyright (c) 2021-2025 RBB S.r.l
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

use rstest::rstest;

use randomness::RngExt;
use test_utils::random::{Seed, make_seedable_rng};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_and_verify(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let key = make_private_key();
    assert_eq!(key.len(), 33);

    let public_key = public_key_from_private_key(&key).unwrap();

    let message_size = rng.random_range(1..=10000);
    let message: Vec<u8> = (0..message_size).map(|_| rng.random::<u8>()).collect();

    let signature = sign_message_for_spending(&key, &message).unwrap();

    {
        // Valid reference signature
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &message).unwrap();
        assert!(verification_result);
    }
    {
        // Tamper with the message
        let mut tampered_message = message.clone();
        let tamper_bit_index = rng.random_range(0..message_size);
        tampered_message[tamper_bit_index] = tampered_message[tamper_bit_index].wrapping_add(1);
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &tampered_message).unwrap();
        assert!(!verification_result);
    }
    {
        // Tamper with the signature
        let mut tampered_signature = signature.clone();
        // Ignore the first byte because the it is the key kind
        let tamper_bit_index = rng.random_range(1..signature.len());
        tampered_signature[tamper_bit_index] = tampered_signature[tamper_bit_index].wrapping_add(1);
        let verification_result =
            verify_signature_for_spending(&public_key, &tampered_signature, &message).unwrap();
        assert!(!verification_result);
    }
    {
        // Wrong keys
        let private_key = make_private_key();
        let public_key = public_key_from_private_key(&private_key).unwrap();
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &message).unwrap();
        assert!(!verification_result);
    }
}

#[test]
fn transaction_get_id() {
    let expected_tx_id = "35a7938c2a2aad5ae324e7d0536de245bf9e439169aa3c16f1492be117e5d0e0";
    let tx_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a";
    let tx_signed_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a0401018d010002eddd003bfb6333123e682abe6923da1d38faa4f0e0d9e2ee42d5aa46c152a34800a749a30c8c9c33696ce407fc145ebc9824e17b778d0d9ccc8129be52f37b74160e60f6689ac2f481071e1a63d9cf0f6eab84c2703b5e9f229cd8188ce092edd4";

    let tx_bin = hex::decode(tx_hex).unwrap();
    let tx_signed_bin = hex::decode(tx_signed_hex).unwrap();

    assert_eq!(get_transaction_id(&tx_bin, true).unwrap(), expected_tx_id);
    assert_eq!(get_transaction_id(&tx_bin, false).unwrap(), expected_tx_id);

    get_transaction_id(&tx_signed_bin, true).unwrap_err();
    assert_eq!(
        get_transaction_id(&tx_signed_bin, false).unwrap(),
        expected_tx_id
    );
}

mod bip39_passphrase_tests {
    use super::*;
    use hex::FromHex;

    /// The same mnemonic as in the JS bindings tests (wasm-wrappers/js-bindings-test).
    const MNEMONIC: &str = "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";

    /// Legacy (empty passphrase) derivations, captured from the pre-passphrase implementation.
    /// These vectors must never change, otherwise existing wallets would recover different keys.
    mod legacy_vectors {
        pub const MAINNET_ACCOUNT_PRIVKEY: &str = "00038000002c80004d4c80000000261ee699496924546a94266597d15e3c081d8aa3b99ccefec2453418fd4e58720134b4486bdb7e70bc23933483a0cb10ac17bc104fd3c42758a4a777d71fda2d";
        pub const MAINNET_RECEIVING_0: &str =
            "00b88adfb44da2c1fd5f12f7996bd147f45bd0b8917fa8842d4c901b965d5dad1f";
        pub const MAINNET_RECEIVING_1: &str =
            "0022b76360c53d567d5130a7de421576c0ec1b745485c01793dbed534d489c017e";
        pub const TESTNET_ACCOUNT_PRIVKEY: &str = "00038000002c80000001800000008fe13ec65ee469346b060206efaebafec23e2c06b5288a5e446aeab3854f13c5bfbc80385eda560749b9601f5f5bd92ed56caf243ecb4f57c97fcb3bf13ad0e6";
        pub const TESTNET_RECEIVING_0: &str =
            "00f42c0e96b4ee90ed64c57948216d7a4773d59969a080ac45f639ee624481590d";
        pub const TESTNET_RECEIVING_1: &str =
            "00114be4d2511116792ca87760973ba299ad94a5a8ddb3ab491ecfa7e62d613745";
    }

    #[test]
    fn legacy_derivations_unchanged() {
        // Regression test: `None`, `Some("")` and the old 2-argument behavior must all
        // produce byte-identical results.
        for passphrase in [None, Some(String::new())] {
            let mainnet_account =
                make_default_account_privkey(MNEMONIC, Network::Mainnet, passphrase.clone())
                    .unwrap();
            assert_eq!(
                mainnet_account,
                Vec::from_hex(legacy_vectors::MAINNET_ACCOUNT_PRIVKEY).unwrap()
            );

            let testnet_account =
                make_default_account_privkey(MNEMONIC, Network::Testnet, passphrase.clone())
                    .unwrap();
            assert_eq!(
                testnet_account,
                Vec::from_hex(legacy_vectors::TESTNET_ACCOUNT_PRIVKEY).unwrap()
            );

            for (idx, expected) in [
                (0, legacy_vectors::MAINNET_RECEIVING_0),
                (1, legacy_vectors::MAINNET_RECEIVING_1),
            ] {
                let receiving = make_receiving_address(&mainnet_account, idx).unwrap();
                assert_eq!(
                    receiving,
                    Vec::from_hex(expected).unwrap(),
                    "mainnet receiving {idx}"
                );
            }

            for (idx, expected) in [
                (0, legacy_vectors::TESTNET_RECEIVING_0),
                (1, legacy_vectors::TESTNET_RECEIVING_1),
            ] {
                let receiving = make_receiving_address(&testnet_account, idx).unwrap();
                assert_eq!(
                    receiving,
                    Vec::from_hex(expected).unwrap(),
                    "testnet receiving {idx}"
                );
            }
        }
    }

    #[test]
    fn bip39_trezor_test_vectors() {
        // Official BIP39 test vectors (https://github.com/trezor/python-mnemonic/blob/master/vectors.json),
        // verified with an independent PBKDF2-HMAC-SHA512 implementation
        // (password = mnemonic, salt = "mnemonic" + passphrase, 2048 iterations, 64 bytes).
        const VECTORS: &[(&str, &str)] = &[
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ),
            (
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ),
            (
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            ),
            (
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            ),
        ];

        for (mnemonic, expected_seed_hex) in VECTORS {
            let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, *mnemonic).unwrap();
            let seed = mnemonic.to_seed("TREZOR");
            assert_eq!(hex::encode(seed), *expected_seed_hex);
        }
    }

    #[test]
    fn different_passphrases_produce_different_keys() {
        let passphrases = [None, Some("passphrase-1".to_owned()), Some("passphrase-2".to_owned())];

        let account_keys = passphrases
            .iter()
            .map(|passphrase| {
                make_default_account_privkey(MNEMONIC, Network::Mainnet, passphrase.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // All extended private keys must be distinct.
        for (i, key1) in account_keys.iter().enumerate() {
            for key2 in &account_keys[i + 1..] {
                assert_ne!(key1, key2);
            }
        }

        // Receiving addresses (at the same index) must be distinct as well. Note that the
        // address only depends on the public key, so this also proves that the actual keys
        // (and not just their encodings) differ.
        let addresses = account_keys
            .iter()
            .map(|account_key| {
                let receiving_privkey = make_receiving_address(account_key, 0).unwrap();
                let public_key = public_key_from_private_key(&receiving_privkey).unwrap();
                pubkey_to_pubkeyhash_address(&public_key, Network::Mainnet).unwrap()
            })
            .collect::<Vec<_>>();

        for (i, addr1) in addresses.iter().enumerate() {
            for addr2 in &addresses[i + 1..] {
                assert_ne!(addr1, addr2);
            }
        }
    }

    #[test]
    fn non_ascii_passphrase_normalization() {
        // BIP39 requires NFKD normalization of the passphrase before PBKDF2; `bip39`'s
        // `to_seed` performs it. Pin the behavior with vectors computed by an independent
        // implementation (Python: unicodedata NFKD + hashlib.pbkdf2_hmac-sha512) so that
        // keys derived here stay compatible with other BIP39 wallets for non-ASCII
        // passphrases.
        const MNEMONIC_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        const VECTORS: &[(&str, &str)] = &[
            // 'ö' (U+00F6) normalizes to 'o' + combining diaeresis; 'ﬀ' (U+FB00) to "ff".
            (
                "pässwörd ﬀ test",
                "e1b23c921466b09c0e76122bf4df2a3f9deed56923aceaaf890b3fbd7a20f7752d47ed755eafb8abb02ea78a1afe21e214bd5be101e2dcb41fb044df8372d92a",
            ),
            // Leading invisible separator (U+202F) and ideographic space (U+3000) normalize
            // to plain spaces.
            (
                "\u{202f}test\u{3000}",
                "6cd25875d7aea5116cc746b82fa1a253ef9b42d1ceb337a0df8623ecdf8f0cae83b2a20c35d7394863dafcaa1ce64c35c0db0a18687448899dd50fd7ce2901d4",
            ),
        ];

        for (passphrase, expected_seed_hex) in VECTORS {
            let mnemonic =
                bip39::Mnemonic::parse_in(bip39::Language::English, MNEMONIC_12).unwrap();
            let seed = mnemonic.to_seed(*passphrase);
            assert_eq!(hex::encode(seed), *expected_seed_hex);
        }
    }

    /// The acceptance gate for passphrase support: Mintlayer Core's key-management crate
    /// (the desktop wallet) and the wasm bindings must derive identical keys/addresses for
    /// the same mnemonic + passphrase.
    #[test]
    fn wasm_matches_core_key_chain() {
        use wallet::key_chain::MasterKeyChain;

        const PASSPHRASE: &str = "correct horse battery staple";

        let chain_config = Builder::new(Network::Mainnet.into()).build();

        // Core desktop path
        let (root_key, _vrf_key, _seed_phrase) =
            MasterKeyChain::mnemonic_to_root_key(MNEMONIC, Some(PASSPHRASE)).unwrap();

        // Derive the default account key using the same path as the wasm function:
        // 44'/<coin_type>'/0'
        let account_path = vec![
            BIP44_PATH,
            chain_config.bip44_coin_type(),
            ChildNumber::from_hardened(U31::ZERO),
        ];
        let core_account_key =
            root_key.derive_absolute_path(&account_path.try_into().unwrap()).unwrap();

        // Wasm path
        let wasm_account_key =
            make_default_account_privkey(MNEMONIC, Network::Mainnet, Some(PASSPHRASE.to_owned()))
                .unwrap();

        assert_eq!(
            wasm_account_key,
            core_account_key.encode(),
            "wasm and core must derive the same account key"
        );

        // And the same receiving address.
        // Derive the receiving key the same way as `make_receiving_address` does
        // (see the `derive` helper in this crate).
        let core_receiving_privkey = core_account_key
            .derive_child(RECEIVE_FUNDS_INDEX)
            .unwrap()
            .derive_child(ChildNumber::from_normal(U31::from_u32_with_msb(0).0))
            .unwrap()
            .private_key();
        let core_public_key = crypto::key::PublicKey::from_private_key(&core_receiving_privkey);
        let core_address = Address::new(
            &chain_config,
            Destination::PublicKeyHash(PublicKeyHash::from(&core_public_key)),
        )
        .unwrap();

        let wasm_receiving_privkey = make_receiving_address(&wasm_account_key, 0).unwrap();
        let wasm_public_key = public_key_from_private_key(&wasm_receiving_privkey).unwrap();
        let wasm_address =
            pubkey_to_pubkeyhash_address(&wasm_public_key, Network::Mainnet).unwrap();

        assert_eq!(wasm_address, core_address.to_string());
    }
}
