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

// Note: genesis must be present.
#[rustfmt::skip]
// The Babbage testnet starts from a fresh genesis; the entry at height 0 is
// the genesis id itself, as for every network.
pub const CHECKPOINTS_DATA: &[(u64, &str)] = &[
    (0, "BB37DAFD5113CC4E7A9A8C51B6F79024394126CFB985FF044A0CBB7AC43A3D5A"),
];
