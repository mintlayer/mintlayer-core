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

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Symmetric key creation from shared secret failed: {0}")]
    SymmetricKeyCreationFailed(String),
    #[error("Symmetric encryption failed: {0}")]
    SymmetricEncryptionFailed(String),
    #[error("Symmetric decryption failed: {0}")]
    SymmetricDecryptionFailed(String),
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}
