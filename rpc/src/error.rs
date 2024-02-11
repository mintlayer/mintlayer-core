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

//! Error handling machinery for RPC

use std::fmt::Display;

/// RPC error
use jsonrpsee::types::{error::CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned};

/// The Result type with RPC-specific error.
pub type RpcResult<T> = jsonrpsee::core::RpcResult<T>;
pub type RpcCallResult<T> = std::result::Result<T, jsonrpsee::MethodsError>;
pub type RpcClientResult<T> = std::result::Result<T, jsonrpsee::core::ClientError>;
pub type Error = ErrorObjectOwned;
pub type ClientError = jsonrpsee::core::ClientError;

/// Handle RPC result
///
/// This is a generic way of converting the likes of:
/// * `R`
/// * `Result<R, E0>`
/// * `Result<Result<R, E0>, E1>`
/// * etc...
///
/// to `rpc::Result<R>`.
///
/// Works provided the errors satisfy the required bounds which are [std::error::Error], [Send],
/// [Sync], and `'static` lifetime. Type annotations for the `R` parameter may be required at times
/// but most of the time type inference will figure it out. In general, nailing down the `R` type
/// is sufficient for the compiler to infer the rest of the generic arguments.
///
/// In particular, using `?` often requires a type annotation:
/// ```ignore
///     let foo: MyFooType = rpc::handle_result(blah)?;
/// ```
///
/// TODO: Maybe this could be generalized to also handle `anyhow::Error` and moved elsewhere?
pub fn handle_result<T: HandleResult<R, I>, R, I>(res: T) -> self::RpcResult<R> {
    res.handle_result()
}

pub trait HandleResult<R, I> {
    fn handle_result(self) -> self::RpcResult<R>;
}

impl<R> HandleResult<R, ()> for R {
    fn handle_result(self) -> self::RpcResult<R> {
        Ok(self)
    }
}

impl<R, T, E, I> HandleResult<R, (I,)> for std::result::Result<T, E>
where
    T: HandleResult<R, I>,
    // Handle both std::error::Error and anyhow::Error
    // TODO: does this seem ok?
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>> + Display,
{
    fn handle_result(self) -> self::RpcResult<R> {
        self.map_err(|err| {
            ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, err.to_string(), None::<()>)
        })
        .and_then(|t| t.handle_result())
    }
}
