// Copyright (c) 2022 RBB S.r.l
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

use bitcoin_bech32::WitnessProgram;
use crypto::random::{distributions::Alphanumeric, make_pseudo_rng, Rng};

use super::Bech32Error;

#[test]
fn check_invalid_addresses() {
    vec![
        (
            "bc10d3rmtg62h747en5j6fju5g5qyvsransrkty6ghh96pu647wumctejlsngh9pf26cy3srxa6",
            "invalid length",
        ),
        (
            "bc10rmfwl8nxdweeyc4sf89t0tn9fv9w6qpyzsnl2r4k48vjqh03qas9asdje0rlr0phqv9smnx",
            "invalid length",
        ),
        (
            "bc1qxmf2d6aerjzam3rur0zufqxqnyqfts5we6pfe",
            "invalid padding",
        ),
        ("bcrt1r5x6gpyc", "invalid padding"),
        (
            "tb13h83rtwq62udrhwpn87uely7cyxcjrj0azz6a4r3n9s87x5uj98ys6ufp83",
            "invalid script version",
        ),
        (
            "tb130lvl2lyugsk2tf3zhwcjjv39dmwt2tt7ytqaexy8edwcuwks6p5scll5kz",
            "invalid script version",
        ),
        (
            "tb13c553hwygcgj48qwmr9f8q0hgdcfklyaye5sxzcpcjnmxv4z506xs90tchn",
            "invalid script version",
        ),
    ]
    .iter()
    .for_each(|&(s, e)| {
        match WitnessProgram::from_address(s) {
            Ok(_) => panic!("this should fail, because the address is invalid."),
            Err(err) => {
                assert_eq!(&err.to_string(), e);
            }
        }

        match super::bech32_decode(s) {
            Ok(decoded) => match super::bech32_encode(decoded.hrp(), decoded.data()) {
                Ok(encoded) => {
                    assert_eq!(s.to_lowercase(), encoded.to_lowercase())
                }
                Err(e) => {
                    panic!("Did not encode: {s:?} Reason: {e:?}")
                }
            },
            Err(e) => {
                panic!("Did not decode: {s:?} Reason: {e:?}")
            }
        }
    });
}

#[test]
fn check_valid_strings() {
    [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllu30cxdc",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
    ].iter().for_each(|s| {
            match super::bech32_decode(s) {
               Ok(decoded) => {
                   match super::bech32_encode(decoded.hrp(), decoded.data()) {
                       Ok(encoded) => { assert_eq!(s.to_lowercase(), encoded.to_lowercase()) }
                       Err(e) => { panic!("Did not encode: {s:?} Reason: {e:?}") }
                   }
               }
               Err(e) => {
                   panic!("Did not decode: {s:?} Reason: {e:?}")
               }
           }
        });
}

#[test]
fn check_invalid_strings() {
    vec![
        (
            " 1xj0phk",
            Bech32Error::DecodeParsingError("invalid human-readable part".to_string()),
        ),
        (
            "\u{7F}1g6xzxy",
            Bech32Error::DecodeParsingError("invalid human-readable part".to_string()),
        ),
        (
            "\u{80}1vctc34",
            Bech32Error::DecodeParsingError("invalid human-readable part".to_string()),
        ),
        ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", Bech32Error::DecodeParsingError("invalid human-readable part".to_string())),
        ("qyrz8wqd2c9m", Bech32Error::DecodeParsingError("character error".to_string())),
        ("1qyrz8wqd2c9m", Bech32Error::DecodeParsingError("invalid human-readable part".to_string())),
        ("y1b0jsk6g", Bech32Error::DecodeParsingError("character error".to_string())),
        ("lt1igcx5c0", Bech32Error::DecodeParsingError("character error".to_string())),
        ("in1muywd", Bech32Error::DecodeChecksumError("the checksummed string is not a valid length".to_string())),
        ("mm1crxm3i", Bech32Error::DecodeParsingError("character error".to_string())),
        ("au1s5cgom", Bech32Error::DecodeParsingError("character error".to_string())),
        ("M1VUXWEZ", Bech32Error::DecodeChecksumError("the checksum residue is not valid for the data".to_string())),
        ("16plkw9", Bech32Error::DecodeParsingError("invalid human-readable part".to_string())),
        ("1p2gdwpf", Bech32Error::DecodeParsingError("invalid human-readable part".to_string())),
        // This is a bech32, not bech32m, address
        ("bech321qqqsyrhqy2a", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        // invalid addresses
        ("bcrt1q8p08mv8echkf3es027u4cdswxlylm3th76ls8v6y4zy4vwsavngpr4e4td", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("bc1q5cuatynjmk4szh40mmunszfzh7zrc5xm9w8ccy", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("bc1qkw7lz3ahms6e0ajv27mzh7g62tchjpmve4afc29u7w49tddydy2syv0087", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("tb1q74fxwnvhsue0l8wremgq66xzvn48jlc5zthsvz", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("tb1qpt7cqgq8ukv92dcraun9c3n0s3aswrt62vtv8nqmkfpa2tjfghesv9ln74", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("tb1q0sqzfp3zj42u0perxr6jahhu4y03uw4dypk6sc", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("tb1q9jv4qnawnuevqaeadn47gkq05ev78m4qg3zqejykdr9u0cm7yutq6gu5dj", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("bc1qz377zwe5awr68dnggengqx9vrjt05k98q3sw2n", Bech32Error::VariantCheckChecksumError("the checksum residue is not valid for the data".to_string())),
        ("tb1qgk665m2auw09rc7pqyf7aulcuhmatz9xqtr5mxew7zuysacaascqs9v0vn", Bech32Error::DecodeChecksumError("the checksum residue is not valid for the data".to_string()))
    ]
    .iter()
    .for_each(|(s, b_err)| match super::bech32_decode(*s) {
        Ok(_) => {
            panic!("Should be invalid: {s:?}")
        }
        Err(e) => {
            assert_eq!(*b_err, e)
        }
    });
}

#[test]
fn check_arbitraty_data_convertion() {
    let test_hrp = "hrp";
    let dataset = vec![
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec(),
        b"z y x w v u t s r q p o n m l k j i h g f e d c b a".to_vec(),
        b"1234567890".to_vec(),
        vec![0],
        Vec::<u8>::new(),
    ];
    for test_data in &dataset {
        let encoded_data = super::bech32_encode(test_hrp, test_data).unwrap();
        let decoded_data = super::bech32_decode(encoded_data).unwrap();
        assert_eq!(test_data, decoded_data.data());
        assert_eq!(test_hrp, decoded_data.hrp());
    }
}

#[test]
fn check_bech32m_convertion_to_arbitraty_chosen_data() {
    let test_hrp = "hrp";
    let dataset = [
        "hrp1g9pyx3z9ger5sj22fdxy6nj02pg4y56524t9wkzetgqqazk6",
        "hrp10gs8jgrcypmjqa3qw5s8ggrnypezqufqwqsx7grwypkjqmpqdvsx5grfyp5zqeeqvcsx2gryyp3jqc3qvyq7p8jc",
        "hrp1xyerxdp4xcmnswfs3y3n8w",
        "hrp1qqh9dn75",
        "hrp1etsu3g",
    ];

    let expected_results = [
        "4142434445464748494a4b4c4d4e4f505152535455565758595a",
        "7a2079207820772076207520742073207220712070206f206e206d206c206b206a206920682067206620652064206320622061",
        "31323334353637383930",
        "00",
        ""
    ];

    for test_data_and_expected_result in dataset.iter().zip(expected_results) {
        let test_data = test_data_and_expected_result.0;
        let expected_result_hex = test_data_and_expected_result.1;
        let expected_result = hex::decode(expected_result_hex).unwrap();
        let decoded_data = super::bech32_decode(test_data).unwrap();
        let encoded_data = super::bech32_encode(test_hrp, decoded_data.data()).unwrap();

        assert_eq!(decoded_data.hrp(), "hrp");
        assert_eq!(decoded_data.data(), expected_result);
        assert_eq!(*test_data, encoded_data);
    }
}

fn bech32m_test_random_data(rng: &mut impl Rng, data_length: usize) {
    let hrp_length = 1 + rng.gen::<usize>() % 10;
    let test_hrp = make_pseudo_rng()
        .sample_iter(&Alphanumeric)
        .take(hrp_length)
        .map(char::from)
        .collect::<String>()
        .to_lowercase();
    let random_bytes: Vec<u8> = (0..data_length).map(|_| rng.gen::<u8>()).collect();

    let encoded_data = super::bech32_encode(&test_hrp, &random_bytes).unwrap();
    let decoded_data = super::bech32_decode(encoded_data).unwrap();
    assert_eq!(random_bytes, decoded_data.data());
    assert_eq!(test_hrp, decoded_data.hrp());
}

#[test]
fn bech32m_check_random_data_convertion_back_and_forth() {
    let mut rng = make_pseudo_rng();
    let data_length = rng.gen::<usize>() % 100;
    bech32m_test_random_data(&mut rng, data_length);
}

#[test]
fn bech32m_empty_hrp_is_empty() {
    let mut rng = make_pseudo_rng();
    let data_length = 10 + rng.gen::<usize>() % 100;
    let random_bytes: Vec<u8> = (0..data_length).map(|_| rng.gen::<u8>()).collect();

    assert_eq!(
        super::bech32_encode("", random_bytes).unwrap_err(),
        super::error::Bech32Error::HrpEmpty
    );
}
