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

use std::{collections::BTreeMap, str::FromStr as _, sync::Arc};

use itertools::Itertools as _;
use rstest::rstest;
use strum::IntoEnumIterator as _;

use chainstate::BlockIndex;
use chainstate_launcher::ChainConfig;
use chainstate_types::{vrf_tools::construct_transcript, BlockStatus, BlockValidationStage};
use common::{
    address::Address,
    chain::{
        self,
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward, ConsensusData},
        Block, GenBlock, Genesis, PoolId,
    },
    primitives::{BlockHeight, Compact, Id, H256},
    Uint256,
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey, VRFReturn};
use mocks::MockChainstateInterface;
use test_utils::{
    random::{
        make_seedable_rng, randomness::SliceRandom, CryptoRng, IteratorRandom as _, Rng, Seed,
    },
    random_ascii_alphanumeric_string,
};

use crate::{dump_blocks::BlockStatusOutput, dump_blocks_generic, BlockOutputField};

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

#[test]
fn dump_blocks_predefined() {
    let genesis = Genesis::new(
        "foo".to_owned(),
        BlockTimestamp::from_int_seconds(12345),
        vec![],
    );
    let chain_config =
        Arc::new(chain::config::create_unit_test_config_builder().genesis_custom(genesis).build());

    let block_infos = vec![
        TestBlockInfo::from_input_info(TestBlockInputInfo {
            height: BlockHeight::new(1),
            is_mainchain: true,
            parent_id: id_from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            timestamp: BlockTimestamp::from_int_seconds(123),
            pool_id: pool_id_from_str(
                "rpool1hd38tvxv3em8wazcvaxhg2fm3r2k9lt69azdcceagsgaa97x4hcqlfytgj",
                &chain_config,
            ),
            target: uint256_from_str(
                "1111110000000000000000000000000000000000000000000000000000000000",
            ),
            chain_trust: uint256_from_str(
                "2222222222222222222222222222222333333333333333333333333333333333",
            ),
            status: BlockStatusOutput::Good,
        }),
        TestBlockInfo::from_input_info(TestBlockInputInfo {
            height: BlockHeight::new(2),
            is_mainchain: true,
            parent_id: id_from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
            timestamp: BlockTimestamp::from_int_seconds(234),
            pool_id: pool_id_from_str(
                "rpool19r5wd2yyr4cdjc4lrhhwey0j47959xq9quf0vxrqqhd984zuhtps87u6an",
                &chain_config,
            ),
            target: uint256_from_str(
                "2222220000000000000000000000000000000000000000000000000000000000",
            ),
            chain_trust: uint256_from_str(
                "3333333333333333333333333333333333444444444444444444444444444444",
            ),
            status: BlockStatusOutput::PartiallyChecked,
        }),
        TestBlockInfo::from_input_info(TestBlockInputInfo {
            height: BlockHeight::new(2),
            is_mainchain: false,
            parent_id: id_from_str(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
            timestamp: BlockTimestamp::from_int_seconds(345),
            pool_id: pool_id_from_str(
                "rpool1jxrvvujqm4plkr7rfshmru8slddw057npf5fwv7t07awtta6ccaq4c9ycx",
                &chain_config,
            ),
            target: uint256_from_str(
                "3333330000000000000000000000000000000000000000000000000000000000",
            ),
            chain_trust: uint256_from_str(
                "4444444444444444444444444444444444455555555555555555555555555555",
            ),
            status: BlockStatusOutput::Unchecked,
        }),
        TestBlockInfo::from_input_info(TestBlockInputInfo {
            height: BlockHeight::new(3),
            is_mainchain: true,
            parent_id: id_from_str(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
            timestamp: BlockTimestamp::from_int_seconds(456),
            pool_id: pool_id_from_str(
                "rpool1gjlw2v8nmr78tcxxp70gp0jnplhkwwyhem720puqa4zhkven0cdsfrrlka",
                &chain_config,
            ),
            target: uint256_from_str(
                "4444440000000000000000000000000000000000000000000000000000000000",
            ),
            chain_trust: uint256_from_str(
                "5555555555555555555555555555555555566666666666666666666666666666",
            ),
            status: BlockStatusOutput::Bad,
        }),
    ];

    let block_infos_by_id = Arc::new(
        block_infos
            .iter()
            .map(|info| ((*info.block_index.block_id()).into(), info.clone()))
            .collect::<BTreeMap<Id<GenBlock>, _>>(),
    );
    let all_block_ids_in_order =
        block_infos.iter().map(|info| *info.block_index.block_id()).collect_vec();

    let mut chainstate = MockChainstateInterface::new();

    chainstate.expect_get_chain_config().return_const(Arc::clone(&chain_config));

    chainstate
        .expect_get_block_id_tree_as_list()
        .returning(move || Ok(all_block_ids_in_order.clone()));

    chainstate.expect_get_block_index_for_any_block().returning({
        let block_infos_by_id = Arc::clone(&block_infos_by_id);
        move |block_id| {
            Ok(Some(
                block_infos_by_id.get(block_id.into()).unwrap().block_index.clone(),
            ))
        }
    });

    chainstate.expect_is_block_in_main_chain().returning({
        let block_infos_by_id = Arc::clone(&block_infos_by_id);
        move |block_id| Ok(block_infos_by_id.get(block_id).unwrap().input_info.is_mainchain)
    });

    // Check all fields
    {
        let output_lines = {
            let mut output = Vec::<u8>::new();

            dump_blocks_generic(
                &chainstate,
                false,
                0,
                &BlockOutputField::iter().collect_vec(),
                &mut output,
            )
            .unwrap();

            String::from_utf8(output).unwrap().lines().map(ToOwned::to_owned).collect_vec()
        };

        let expected_output_lines = vec![
            "height,is_mainchain,id,timestamp,pool_id,target,chain_trust,status,parent_id".to_owned(),
            "0,y,ac50d72a82f0dad2033ea2d2e36fdab486cdb8d5088d1d7eb7d85c71c05d5e5d,12345,-,-,-,g,-".to_owned(),
            "1,y,2f1b62916aa3fc731b27fec1ddbfca06b75715d68f51bcbc6f3107714cb69a71,123,rpool1hd38tvxv3em8wazcvaxhg2fm3r2k9lt69azdcceagsgaa97x4hcqlfytgj,1111110000000000000000000000000000000000000000000000000000000000,2222222222222222222222222222222333333333333333333333333333333333,g,1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            "2,y,96d754b644e350312850aac926a5b290809d8084fd63de765036c44054c1c8b6,234,rpool19r5wd2yyr4cdjc4lrhhwey0j47959xq9quf0vxrqqhd984zuhtps87u6an,2222220000000000000000000000000000000000000000000000000000000000,3333333333333333333333333333333333444444444444444444444444444444,p,2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            "2,n,a7b5752f6d3aceeaef461f1171b7b6a39f8c4c30e4c2e7e5bab243bb001ea411,345,rpool1jxrvvujqm4plkr7rfshmru8slddw057npf5fwv7t07awtta6ccaq4c9ycx,3333330000000000000000000000000000000000000000000000000000000000,4444444444444444444444444444444444455555555555555555555555555555,u,3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
            "3,y,dc863d845e864a902986a1fcb813a6346c83ebc8198db5f710759e00f590f86f,456,rpool1gjlw2v8nmr78tcxxp70gp0jnplhkwwyhem720puqa4zhkven0cdsfrrlka,4444440000000000000000000000000000000000000000000000000000000000,5555555555555555555555555555555555566666666666666666666666666666,b,4444444444444444444444444444444444444444444444444444444444444444".to_owned()
        ];
        assert_eq!(output_lines, expected_output_lines);
    }

    // Check some of the fields
    {
        let output_lines = {
            let mut output = Vec::<u8>::new();

            dump_blocks_generic(
                &chainstate,
                false,
                0,
                &[
                    // Note: IsMainchain and Height are swapped compared to the "default" order.
                    BlockOutputField::IsMainchain,
                    BlockOutputField::Height,
                    BlockOutputField::Timestamp,
                ],
                &mut output,
            )
            .unwrap();

            String::from_utf8(output).unwrap().lines().map(ToOwned::to_owned).collect_vec()
        };

        let expected_output_lines = vec![
            "is_mainchain,height,timestamp".to_owned(),
            "y,0,12345".to_owned(),
            "y,1,123".to_owned(),
            "y,2,234".to_owned(),
            "n,2,345".to_owned(),
            "y,3,456".to_owned(),
        ];
        assert_eq!(output_lines, expected_output_lines);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn dump_blocks_random(
    #[case] seed: Seed,
    #[values(false, true)] mainchain_only: bool,
    #[values(false, true)] start_from_zero_height: bool,
) {
    let mut rng = make_seedable_rng(seed);

    let genesis_msg = random_ascii_alphanumeric_string(&mut rng, 10..20);
    let genesis_timestamp = BlockTimestamp::from_int_seconds(rng.gen_range(0..1_000_000));
    let genesis = Genesis::new(genesis_msg, genesis_timestamp, vec![]);
    let chain_config =
        Arc::new(chain::config::create_unit_test_config_builder().genesis_custom(genesis).build());

    let mainchain_block_count = rng.gen_range(10..20);
    let stale_block_count = rng.gen_range(0..mainchain_block_count);

    let block_infos = {
        let mut infos = Vec::new();

        for i in 0..mainchain_block_count {
            let height = BlockHeight::new(i + 1);
            let input_info = TestBlockInputInfo::from_rng(height, true, &mut rng);
            infos.push(TestBlockInfo::from_input_info(input_info));
        }

        if !mainchain_only {
            for _ in 0..stale_block_count {
                let height = BlockHeight::new(rng.gen_range(1..=mainchain_block_count));
                let input_info = TestBlockInputInfo::from_rng(height, false, &mut rng);
                infos.push(TestBlockInfo::from_input_info(input_info));
            }

            infos.shuffle(&mut rng);
            infos.sort_by(|b1, b2| b1.input_info.height.cmp(&b2.input_info.height));
        }

        infos
    };
    let block_infos_by_id = Arc::new(
        block_infos
            .iter()
            .map(|info| ((*info.block_index.block_id()).into(), info.clone()))
            .collect::<BTreeMap<Id<GenBlock>, _>>(),
    );
    let all_block_ids_in_order =
        block_infos.iter().map(|info| *info.block_index.block_id()).collect_vec();

    let mut chainstate = MockChainstateInterface::new();

    chainstate.expect_get_chain_config().return_const(Arc::clone(&chain_config));

    if mainchain_only {
        chainstate
            .expect_get_mainchain_blocks_list()
            .returning(move || Ok(all_block_ids_in_order.clone()));
    } else {
        chainstate
            .expect_get_block_id_tree_as_list()
            .returning(move || Ok(all_block_ids_in_order.clone()));
    }

    chainstate.expect_get_block_index_for_any_block().returning({
        let block_infos_by_id = Arc::clone(&block_infos_by_id);
        move |block_id| {
            Ok(Some(
                block_infos_by_id.get(block_id.into()).unwrap().block_index.clone(),
            ))
        }
    });
    if !mainchain_only {
        chainstate.expect_is_block_in_main_chain().returning({
            let block_infos_by_id = Arc::clone(&block_infos_by_id);
            move |block_id| Ok(block_infos_by_id.get(block_id).unwrap().input_info.is_mainchain)
        });
    }

    let start_height = if start_from_zero_height {
        0
    } else {
        rng.gen_range(1..=mainchain_block_count)
    };

    let starting_block_info_index = block_infos
        .iter()
        .position(|info| info.input_info.height.into_int() >= start_height)
        .unwrap();

    let output_lines = {
        let mut output = Vec::<u8>::new();

        let fields = BlockOutputField::iter().collect_vec();
        dump_blocks_generic(
            &chainstate,
            mainchain_only,
            start_height,
            &fields,
            &mut output,
        )
        .unwrap();

        String::from_utf8(output).unwrap().lines().map(ToOwned::to_owned).collect_vec()
    };

    let expected_output_lines = {
        let mut lines = Vec::new();
        lines.push(expected_header_for_default_field_order().to_owned());
        if start_from_zero_height {
            lines.push(expected_genesis_output_line_for_default_field_order(
                &chain_config,
            ));
        }
        for info in &block_infos[starting_block_info_index..] {
            lines.push(expected_output_line_for_default_field_order(
                info,
                &chain_config,
            ));
        }

        lines
    };

    assert_eq!(output_lines, expected_output_lines);
}

#[derive(Clone)]
struct TestBlockInputInfo {
    // Note: the only thing the dumper checks is that the returned blocks are ordered by height
    // and there are no gaps between them. So, these two fields cannot be absolutely arbitrary.
    height: BlockHeight,
    is_mainchain: bool,

    // But the rest of them can.
    parent_id: Id<GenBlock>,
    timestamp: BlockTimestamp,
    pool_id: PoolId,
    target: Uint256,
    chain_trust: Uint256,
    status: BlockStatusOutput,
    // Also note that we don't have the block id here, this is because BlockIndex (which we
    // need to return from chainstate) only accepts an entire block and calculates the id
    // on its own.
}

impl TestBlockInputInfo {
    fn from_rng(
        height: BlockHeight,
        is_mainchain: bool,
        rng: &mut (impl Rng + CryptoRng),
    ) -> TestBlockInputInfo {
        Self {
            height,
            is_mainchain,
            parent_id: Id::random_using(rng),
            timestamp: BlockTimestamp::from_int_seconds(rng.gen()),
            pool_id: PoolId::random_using(rng),
            target: gen_target(rng),
            chain_trust: Uint256::from_bytes(rng.gen()),
            status: BlockStatusOutput::iter().choose(rng).unwrap(),
        }
    }
}

#[derive(Clone)]
struct TestBlockInfo {
    input_info: TestBlockInputInfo,
    // The BlockIndex that contains the input info as well as the block id.
    block_index: BlockIndex,
}

impl TestBlockInfo {
    fn from_input_info(input_info: TestBlockInputInfo) -> Self {
        let block = Block::new(
            vec![],
            input_info.parent_id,
            input_info.timestamp,
            make_consensus_data(input_info.pool_id, input_info.target.into()),
            BlockReward::new(vec![]),
        )
        .unwrap();

        let block_status = match input_info.status {
            BlockStatusOutput::Bad => bad_block_status(),
            BlockStatusOutput::Unchecked => {
                BlockStatus::new_at_stage(BlockValidationStage::Unchecked)
            }
            BlockStatusOutput::PartiallyChecked => {
                BlockStatus::new_at_stage(BlockValidationStage::CheckBlockOk)
            }
            BlockStatusOutput::Good => {
                BlockStatus::new_at_stage(BlockValidationStage::FullyChecked)
            }
        };
        let block_index = BlockIndex::new(
            &block,
            input_info.chain_trust,
            // some_ancestor - doesn't matter
            Id::zero(),
            input_info.height,
            // chain_time_max - doesn't matter
            BlockTimestamp::from_int_seconds(0),
            // chain_transaction_count - doesn't matter
            0,
            block_status,
        );

        Self {
            input_info,
            block_index,
        }
    }
}

// This assumes that the fields list has been obtained via BlockOutputField::iter().collect_vec().
fn expected_header_for_default_field_order() -> &'static str {
    "height,is_mainchain,id,timestamp,pool_id,target,chain_trust,status,parent_id"
}

fn expected_genesis_output_line_for_default_field_order(chain_config: &ChainConfig) -> String {
    let id = chain_config.genesis_block_id();
    let ts = chain_config.genesis_block().timestamp().as_int_seconds();
    let status = BlockStatusOutput::Good.to_string();
    format!("0,y,{id:x},{ts},-,-,-,{status},-")
}

// Same assumption about field list order as above.
fn expected_output_line_for_default_field_order(
    info: &TestBlockInfo,
    chain_config: &ChainConfig,
) -> String {
    let height = info.input_info.height;
    let is_mc = if info.input_info.is_mainchain {
        "y"
    } else {
        "n"
    };
    let id = info.block_index.block_id();
    let ts = info.input_info.timestamp.as_int_seconds();
    let pool_id = Address::new(chain_config, info.input_info.pool_id).unwrap().into_string();
    let target = info.input_info.target;
    let ctrust = info.input_info.chain_trust;
    let status = info.input_info.status.to_string();
    let parent_id = info.input_info.parent_id;

    format!("{height},{is_mc},{id:x},{ts},{pool_id},{target:x},{ctrust:x},{status},{parent_id:x}")
}

fn bad_block_status() -> BlockStatus {
    let mut status = BlockStatus::new();
    status.set_validation_failed();
    status
}

fn make_consensus_data(pool_id: PoolId, compact_target: Compact) -> ConsensusData {
    // Create a new rng based on pool id, so that this function can be used in deterministic scenarios.
    let mut rng = make_seedable_rng(Seed(pool_id.as_hash().to_low_u64_le()));
    let vrf_return = bogus_vrf_return(&mut rng);

    ConsensusData::PoS(Box::new(PoSData::new(
        vec![],
        vec![],
        pool_id,
        vrf_return,
        compact_target,
    )))
}

fn bogus_vrf_return(rng: &mut (impl Rng + CryptoRng)) -> VRFReturn {
    let (vrf_sk, _) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let vrf_transcript = construct_transcript(
        rng.gen(),
        &rng.gen(),
        BlockTimestamp::from_int_seconds(rng.gen()),
    )
    .with_rng(rng);

    vrf_sk.produce_vrf_data(vrf_transcript)
}

fn gen_compact_target(rng: &mut (impl Rng + CryptoRng)) -> Compact {
    let target = Uint256::from_bytes(rng.gen());
    target.into()
}

fn gen_target(rng: &mut (impl Rng + CryptoRng)) -> Uint256 {
    gen_compact_target(rng).try_into().unwrap()
}

fn id_from_str<T>(s: &str) -> Id<T> {
    Id::new(H256::from_str(s).unwrap())
}

fn pool_id_from_str(s: &str, chain_config: &ChainConfig) -> PoolId {
    Address::from_string(chain_config, s.to_owned()).unwrap().into_object()
}

fn uint256_from_str(s: &str) -> Uint256 {
    let data = hex::decode(s).unwrap();
    Uint256::from_be_slice(&data).unwrap()
}
