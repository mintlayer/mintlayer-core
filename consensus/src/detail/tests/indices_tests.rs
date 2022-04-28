// Copyright (c) 2021 RBB S.r.l
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
// Author(s): S. Afach

use crate::detail::tests::*;

#[test]
fn test_indices_calculations() {
    let block = generate_random_invalid_block();
    let serialized_block = block.encode();
    let serialized_header = block.header().encode();
    let serialized_transactions = block.transactions().encode();
    assert_eq!(
        // +1 for the enum arm byte
        1 + serialized_header.len() + serialized_transactions.len(),
        serialized_block.len(),
    );
    // TODO: calculate block reward position
    for (tx_num, tx) in block.transactions().iter().enumerate() {
        let tx_index = calculate_tx_index_from_block(&block, tx_num).unwrap();
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(tx_index.get_output_count(), tx.get_outputs().len() as u32);

        let pos = match tx_index.get_position() {
            common::chain::SpendablePosition::Transaction(pos) => pos,
            common::chain::SpendablePosition::BlockReward(_) => unreachable!(),
        };
        let tx_start_pos = pos.get_byte_offset_in_block() as usize;
        let tx_end_pos =
            pos.get_byte_offset_in_block() as usize + pos.get_serialized_size() as usize;
        let tx_serialized_in_block = &serialized_block[tx_start_pos..tx_end_pos];
        let tx_serialized = tx.encode();
        assert_eq!(tx_serialized_in_block, tx_serialized);

        // to ensure Vec comparison is correct since I'm a paranoid C++ dude, let's mess things up
        let tx_messed = tx_serialized.iter().map(|c| c.wrapping_add(1)).collect::<Vec<u8>>();
        assert!(tx_serialized_in_block != tx_messed);
    }
}
