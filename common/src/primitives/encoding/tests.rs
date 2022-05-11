use super::*;
use bech32::ToBase32;
use bitcoin_bech32::WitnessProgram;
use hex::FromHex;
use logging::log;

#[test]
fn check_encode() {
    logging::init_logging::<&std::path::Path>(None);

    let data = vec![0x00, 0x01, 0x02];
    let hrp = "bech32";

    let encoded = super::bech32m::base32_to_bech32m(hrp, data.clone()).expect("it should not fail");
    assert_eq!(encoded, "bech321qpzq0geym".to_string());

    let decoded = super::bech32m::bech32m_to_base32(&encoded).expect("should decode okay");
    log::info!("value of decoded: {:?}", decoded);

    assert_eq!(hrp, decoded.get_hrp());
    assert_eq!(data, decoded.get_data());
}

#[test]
fn check_valid_addresses() {
    // (the address, the version and length, the pubkey)
    vec![
        (
            "tb1ph9v3e8nxct57hknlkhkz75p5pnxnkn05cw8ewpxu6tek56g29xgqydzfu7",
            "5120",
            "b9591c9e66c2e9ebda7fb5ec2f50340ccd3b4df4c38f9704dcd2f36a690a2990",
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "5120",
            "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "tb1pmcdc5d8gr92rtemfsnhpeqanvs0nr82upn5dktxluz9n0qcv34lqxke0wq",
            "5120",
            "de1b8a34e8195435e76984ee1c83b3641f319d5c0ce8db2cdfe08b37830c8d7e",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "5120",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        (
            "bc1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzmsspvr7j",
            "5120",
            "a0d0c06640b95b78f965416ad6971b3b1609c3cd9b512aaa39439088211868b7",
        ),
        ("bc1zr4pq63udck", "5202", "1d42"),
        (
            "tb1ray6e8gxfx49ers6c4c70l3c8lsxtcmlx",
            "5310",
            "e93593a0c9354b91c358ae3cffc707fc",
        ),
        (
            "tb1pxqf7d825wjtcftj7uep8w24jq3tz8vudfaqj20rns8ahqya56gcs92eqtu",
            "5120",
            "3013e69d54749784ae5ee642772ab2045623b38d4f41253c7381fb7013b4d231",
        ),
        (
            "tb1rsrzkyvu2rt0dcgexajtazlw5nft4j7494ay396q6auw9375wxsrsgag884",
            "5320",
            "80c562338a1adedc2326ec97d17dd49a57597aa5af4912e81aef1c58fa8e3407",
        ),
        (
            "bcrt1p3xat2ryucc2v0adrktqnavfzttvezrr27ngltsa2726p2ehvxz4se722v2",
            "5120",
            "89bab50c9cc614c7f5a3b2c13eb1225ad9910c6af4d1f5c3aaf2b41566ec30ab",
        ),
        (
            "bcrt1saflydw6e26xhp29euhy5jke5jjqyywk3wvtc9ulgw9dvxyuqy9hdnxthyw755c7ldavy7u",
            "6028",
            "ea7e46bb59568d70a8b9e5c9495b349480423ad1731782f3e8715ac31380216ed9997723bd4a63df",
        ),
        (
            "bc1ps8cndas60cntk8x79sg9f5e5jz7x050z8agyugln2ukkks23rryqpejzkc",
            "5120",
            "81f136f61a7e26bb1cde2c1054d33490bc67d1e23f504e23f3572d6b415118c8",
        ),
        ("bc1zn4tsczge9l", "5202", "9d57"),
    ]
    .iter()
    .for_each(|&(s, version_and_len, d)| {
        let (version, data) = {
            let prog = match WitnessProgram::from_address(s) {
                Ok(prog) => prog,
                Err(e) => panic!("something {:?}", e.to_string()),
            };

            (
                prog.version().to_u8(),
                prog.program()
                    .to_base32()
                    .into_iter()
                    .map(|elem| elem.to_u8())
                    .collect::<Vec<u8>>(),
            )
        };

        match super::bech32m::bech32m_to_base32(s) {
            Ok(decoded) => {
                // check the result of our decoder vs bitcoin_bech32 decoder.
                assert_eq!(version, decoded.get_data()[0]);
                assert_eq!(data, decoded.get_data()[1..]);

                // compare the result of our decoder against the expected data.
                let data_x = {
                    let string_data =
                        Vec::from_hex(d).expect("should not fail to convert to Vec<u8>");
                    string_data.to_base32().into_iter().map(|d| d.to_u8()).collect::<Vec<u8>>()
                };
                assert_eq!(data_x, decoded.get_data()[1..]);

                // compare the result of our decoder against the expected version.
                let version_x = {
                    let version_and_len = Vec::from_hex(version_and_len)
                        .expect("should not fail to convert to Vec<u8>");

                    if version_and_len[0] == 0 {
                        0
                    } else {
                        version_and_len[0] - 0x50
                    }
                };
                assert_eq!(version_x, decoded.get_data()[0]);

                match super::bech32m::base32_to_bech32m(
                    decoded.get_hrp(),
                    <&[u8]>::clone(&decoded.get_data()),
                ) {
                    Ok(encoded) => {
                        assert_eq!(s.to_lowercase(), encoded.to_lowercase())
                    }
                    Err(e) => {
                        panic!("Did not encode: {:?} Reason: {:?}", s, e)
                    }
                }
            }
            Err(e) => {
                panic!("Did not decode: {:?} Reason: {:?}", s, e)
            }
        }
    });
}

#[test]
fn check_invalid_addresses() {
    vec![
        (
            "bc10d3rmtg62h747en5j6fju5g5qyvsransrkty6ghh96pu647wumctejlsngh9pf26cysrys2x2",
            "invalid length",
        ),
        (
            "bc10rmfwl8nxdweeyc4sf89t0tn9fv9w6qpyzsnl2r4k48vjqh03qas9asdje0rlr0phru0wqw0p",
            "invalid length",
        ),
        (
            "bc1qxmf2d6aerjzam3rur0zufqxqnyqfts5u302s7x",
            "invalid Bech32 encoding",
        ),
        ("bcrt1rhsveeudk", "invalid length"),
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
        ("bcrt1rhsveeudk", "invalid length"),
    ]
    .iter()
    .for_each(|&(s, e)| {
        match WitnessProgram::from_address(s) {
            Ok(_) => panic!("this should fail, because the address is invalid."),
            Err(err) => {
                assert_eq!(&err.to_string(), e);
            }
        }

        match super::bech32m::bech32m_to_base32(s) {
            Ok(decoded) => match decoded.encode() {
                Ok(encoded) => {
                    assert_eq!(s.to_lowercase(), encoded.to_lowercase())
                }
                Err(e) => {
                    panic!("Did not encode: {:?} Reason: {:?}", s, e)
                }
            },
            Err(e) => {
                panic!("Did not decode: {:?} Reason: {:?}", s, e)
            }
        }
    });
}

#[test]
fn check_valid_strings() {
    vec!(
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ).iter().for_each(|s| {
            match super::bech32m::bech32m_to_base32(*s) {
               Ok(decoded) => {
                   match super::bech32m::base32_to_bech32m(decoded.get_hrp(), <&[u8]>::clone(&decoded.get_data())) {
                       Ok(encoded) => { assert_eq!(s.to_lowercase(), encoded.to_lowercase()) }
                       Err(e) => { panic!("Did not encode: {:?} Reason: {:?}",s,e) }
                   }
               }
               Err(e) => {
                   panic!("Did not decode: {:?} Reason: {:?}", s, e)
               }
           }
        });
}

#[test]
fn check_invalid_strings() {
    vec!(
            (" 1xj0phk", Bech32Error::InvalidChar(' ')),
            ("\u{7F}1g6xzxy", Bech32Error::InvalidChar('\u{7f}')),
            ("\u{80}1vctc34", Bech32Error::InvalidChar('Â')),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", Bech32Error::InvalidLength),
            ("qyrz8wqd2c9m", Bech32Error::NoSeparator),
            ("1qyrz8wqd2c9m", Bech32Error::InvalidLength),
            ("y1b0jsk6g", Bech32Error::InvalidChar('b')),
            ("lt1igcx5c0", Bech32Error::InvalidChar('i')),
            ("in1muywd", Bech32Error::InvalidLength),
            ("mm1crxm3i", Bech32Error::InvalidChar('i')),
            ("au1s5cgom", Bech32Error::InvalidChar('o')),
            ("M1VUXWEZ", Bech32Error::FailedChecksum),
            ("16plkw9", Bech32Error::InvalidLength),
            ("1p2gdwpf", Bech32Error::InvalidLength),
            ("bech321qqqsyrhqy2a", Bech32Error::UnsupportedVariant),
            // invalid addresses
            ("bcrt1q8p08mv8echkf3es027u4cdswxlylm3th76ls8v6y4zy4vwsavngpr4e4td", Bech32Error::UnsupportedVariant),
            ("bc1q5cuatynjmk4szh40mmunszfzh7zrc5xm9w8ccy", Bech32Error::UnsupportedVariant),
            ("bc1qkw7lz3ahms6e0ajv27mzh7g62tchjpmve4afc29u7w49tddydy2syv0087", Bech32Error::UnsupportedVariant),
            ("tb1q74fxwnvhsue0l8wremgq66xzvn48jlc5zthsvz", Bech32Error::UnsupportedVariant),
            ("tb1qpt7cqgq8ukv92dcraun9c3n0s3aswrt62vtv8nqmkfpa2tjfghesv9ln74", Bech32Error::UnsupportedVariant),
            ("tb1q0sqzfp3zj42u0perxr6jahhu4y03uw4dypk6sc", Bech32Error::UnsupportedVariant),
            ("tb1q9jv4qnawnuevqaeadn47gkq05ev78m4qg3zqejykdr9u0cm7yutq6gu5dj", Bech32Error::UnsupportedVariant),
            ("bc1qz377zwe5awr68dnggengqx9vrjt05k98q3sw2n", Bech32Error::UnsupportedVariant),
            ("tb1qgk665m2auw09rc7pqyf7aulcuhmatz9xqtr5mxew7zuysacaascqs9v0vn", Bech32Error::FailedChecksum)
        ).iter().for_each(|(s,b_err)| {
            match super::decode(*s) {
                Ok(_) => { panic!("Should be invalid: {:?}", s) }
                Err(e) => { assert_eq!(*b_err,e) }
            }
        });
}
