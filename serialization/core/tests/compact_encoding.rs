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

mod utils;

use serialization_core::{Decode, Encode};
use utils::CompactWrapper;

#[test]
fn test_scale_compact_numbers() {
    // Numbers
    let enc = CompactWrapper::encode(&CompactWrapper::new(12u8));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(12u8)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u8));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u8)));

    // 16-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(1234u16));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(1234u16)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u16));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u16)));

    // 32-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(123456u32));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(123456u32)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u32));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u32)));

    // 64-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(123456789u64));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(123456789u64)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u64));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u64)));

    // 128-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(1234567891011121314u128));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(1234567891011121314u128)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u128));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u128)));
}
