// Copyright (c) 2021-2024 RBB S.r.l
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

use std::{collections::BTreeMap, fmt::Write, str::FromStr};

use crate::{
    chain::GenBlock,
    primitives::{BlockHeight, Id, H256},
};

mod mainnet;
mod testnet;

pub fn print_block_heights_ids_as_checkpoints_data(
    heights_ids: &[(BlockHeight, Id<GenBlock>)],
) -> String {
    let fmt = || -> Result<String, std::fmt::Error> {
        let mut output = String::new();
        writeln!(&mut output, "[")?;
        for (height, id) in heights_ids {
            writeln!(&mut output, "    ({}, \"{:X}\"),", height.into_int(), id)?;
        }
        write!(&mut output, "]")?;

        Ok(output)
    };

    fmt().expect("Writing to string must not fail")
}

lazy_static::lazy_static! {
    pub static ref MAINNET_CHECKPOINTS: BTreeMap<BlockHeight, Id<GenBlock>> = {
        make_checkpoints(mainnet::CHECKPOINTS_DATA).expect("corrupted mainnet checkpoints data")
    };
}

lazy_static::lazy_static! {
    pub static ref TESTNET_CHECKPOINTS: BTreeMap<BlockHeight, Id<GenBlock>> = {
        make_checkpoints(testnet::CHECKPOINTS_DATA).expect("corrupted mainnet checkpoints data")
    };
}

fn make_checkpoints(
    checkpoints_data: &[(u64, &str)],
) -> Result<BTreeMap<BlockHeight, Id<GenBlock>>, fixed_hash::rustc_hex::FromHexError> {
    let checkpoints_iter = checkpoints_data.iter().map(|(height, id_str)| {
        let id = H256::from_str(id_str)?.into();
        Ok((BlockHeight::new(*height), id))
    });

    itertools::process_results(checkpoints_iter, |iter| iter.collect::<BTreeMap<_, _>>())
}

#[cfg(test)]
mod tests {
    use crate::primitives::H256;

    use super::*;

    #[test]
    fn test_print_block_heights_ids_as_checkpoints_data() {
        let data = [
            (
                BlockHeight::new(123),
                H256::from_str("8DCDB5157883226DC392DAF440077089152A1BC81ACD8E3F96DCC9CE1F330B10")
                    .unwrap()
                    .into(),
            ),
            (
                BlockHeight::new(234),
                H256::from_str("19A824A331C5879C1C27BF5980B8F820F049CA1D98CDE33AD23DBB5CAEEAA013")
                    .unwrap()
                    .into(),
            ),
            (
                BlockHeight::new(345),
                H256::from_str("D73D6C2C5A7387B9F842C421EF70D00AFABE90E75E1655D08E8F31F22D697C37")
                    .unwrap()
                    .into(),
            ),
        ];

        let printed_str = print_block_heights_ids_as_checkpoints_data(&data);
        let expected_str = indoc::indoc! {r#"
            [
                (123, "8DCDB5157883226DC392DAF440077089152A1BC81ACD8E3F96DCC9CE1F330B10"),
                (234, "19A824A331C5879C1C27BF5980B8F820F049CA1D98CDE33AD23DBB5CAEEAA013"),
                (345, "D73D6C2C5A7387B9F842C421EF70D00AFABE90E75E1655D08E8F31F22D697C37"),
            ]"#};

        assert_eq!(printed_str, expected_str);
    }
}
