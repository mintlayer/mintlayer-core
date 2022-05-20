// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::detail::tests::*;

#[test]
fn test_get_locator() {
    common::concurrency::model(|| {
        let config = Arc::new(create_mainnet());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(Arc::clone(&config), storage).unwrap();

        let mut prev_block = consensus.chain_config.genesis_block().clone();
        let limit = rand::thread_rng().gen::<u16>();

        for _ in 0..limit {
            let new_block = produce_test_block(&consensus.chain_config, &prev_block, false);
            consensus
                .process_block(new_block.clone(), BlockSource::Peer(1))
                .ok()
                .flatten()
                .unwrap();
            prev_block = new_block;
        }
        let locator = consensus.get_locator().unwrap();

        // only genesis
        if limit == 0 {
            assert_eq!(locator.len(), 1);
        } else {
            assert_eq!(locator.len(), (limit as f64).log2().floor() as usize + 2);
        }

        // verify that the locator selected correct headers
        let height =
            consensus.get_block_height_in_main_chain(&prev_block.get_id()).unwrap().unwrap();
        assert_eq!(&locator[0], prev_block.header());
        let iter = locator.iter().skip(1);

        for (header, i) in iter.zip(0..locator.len() - 1) {
            let idx = height - BlockDistance::new(2i64.pow(i as u32));
            let correct = consensus.get_header_from_height(&idx.unwrap()).unwrap().unwrap();
            assert_eq!(&correct, header);
        }
    });
}
