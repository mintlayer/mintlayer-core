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
// Author(s): A. Altonen
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::P2pError;
    use crate::net::mock::{MockService, NetworkService};

    #[tokio::test]
    async fn test_new() {
        let srv_ipv4 = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert_eq!(srv_ipv4.is_ok(), true);

        // address already in use
        let err = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert_eq!(err.is_err(), true);

        // bind to IPv6 localhost
        let srv_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert_eq!(srv_ipv6.is_ok(), true);

        // address already in use
        let s_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert_eq!(err.is_err(), true);
    }
}
