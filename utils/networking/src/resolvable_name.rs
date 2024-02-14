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

use thiserror::Error;

pub trait ResolvableName {
    type ResolvedAddress;

    // Note: if using an async func here, rust warns that use of "async fn in public traits is
    // discouraged as auto trait bounds cannot be specified" and suggests to manually desugar it
    // to "fn xxx() -> impl Future", which we do.
    fn resolve(
        &self,
    ) -> impl std::future::Future<
        Output = Result<impl Iterator<Item = Self::ResolvedAddress> + '_, NameResolutionError>,
    >;
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum NameResolutionError {
    #[error("Cannot resolve '{resolvable_name}' ({error_str})")]
    CannotResolve {
        resolvable_name: String,
        // Note: std::io::Error is not clonable and the ErrorKind that is produced by a failed
        // resolution is not informative at all (it's ErrorKind::Uncategorized), so we store
        // the error as a string.
        error_str: String,
    },
}

/// Resolve the passed names. If a name resolves to multiple addresses, all of them
/// will be returned.
pub async fn resolve_all<R: ResolvableName>(
    resolvables: impl Iterator<Item = R>,
) -> Result<Vec<R::ResolvedAddress>, NameResolutionError> {
    let mut result = Vec::with_capacity(resolvables.size_hint().0);

    for resolvable in resolvables {
        result.extend(resolvable.resolve().await?);
    }

    Ok(result)
}

/// Resolve the passed names. If a name resolves to multiple addresses, only the first of them
/// will be returned.
pub async fn resolve_all_take_first<R: ResolvableName>(
    resolvables: impl Iterator<Item = R>,
) -> Result<Vec<R::ResolvedAddress>, NameResolutionError> {
    let mut result = Vec::with_capacity(resolvables.size_hint().0);

    for resolvable in resolvables {
        result.extend(resolvable.resolve().await?.next().into_iter());
    }

    Ok(result)
}
