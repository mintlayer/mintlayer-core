// Copyright (c) 2023 RBB S.r.l
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

use chainstate::{ban_score::BanScore, BlockError, ChainstateError, CheckBlockError};
use consensus::{ConsensusPoSError, ConsensusVerificationError};

use crate::error::P2pError;

#[test]
fn ban_scores() {
    // Test that ChainstateError p2p errors are reported correctly
    // (there was a bug where the NoKernel error had a score of 20).
    assert_eq!(
        P2pError::ChainstateError(ChainstateError::ProcessBlockError(
            BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::PoSError(ConsensusPoSError::NoKernel),
            )),
        ))
        .ban_score(),
        100
    );
}
