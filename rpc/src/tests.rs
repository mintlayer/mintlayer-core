// Copyright (c) 2022-2024 RBB S.r.l
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

use std::path::PathBuf;

use super::*;
use crypto::random::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[rpc(server, namespace = "some_subsystem")]
pub trait SubsystemRpc {
    #[method(name = "name")]
    fn name(&self) -> RpcResult<String>;

    #[method(name = "add")]
    fn add(&self, a: u64, b: u64) -> RpcResult<u64>;
}

#[rpc(server, namespace = "example_server")]
trait RpcInfo {
    #[method(name = "protocol_version")]
    fn protocol_version(&self) -> RpcResult<String>;
}

struct RpcInfo;
impl RpcInfoServer for RpcInfo {
    fn protocol_version(&self) -> RpcResult<String> {
        Ok("version1".into())
    }
}

pub struct SubsystemRpcImpl;

impl SubsystemRpcServer for SubsystemRpcImpl {
    fn name(&self) -> RpcResult<String> {
        Ok("sub1".into())
    }

    fn add(&self, a: u64, b: u64) -> RpcResult<u64> {
        Ok(a + b)
    }
}

#[tokio::test]
async fn method_list() -> anyhow::Result<()> {
    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let rpc = Builder::new(http_bind_address, None)
        .with_method_list("method_list")
        .register(SubsystemRpcImpl.into_rpc())
        .build()
        .await?;

    let url = format!("http://{}", rpc.http_address());
    let client = new_http_client(url, RpcAuthData::None).unwrap();
    let response: RpcClientResult<Vec<String>> = client.request("method_list", [(); 0]).await;
    assert_eq!(
        response.unwrap(),
        vec!["method_list", "some_subsystem_add", "some_subsystem_name"]
    );

    subsystem::Subsystem::shutdown(rpc).await;
    Ok(())
}

#[rstest]
#[trace]
#[case(true)]
#[case(false)]
#[tokio::test]
async fn rpc_server(#[case] http: bool) -> anyhow::Result<()> {
    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let rpc = Builder::new(http_bind_address, None)
        .register(SubsystemRpcImpl.into_rpc())
        .register(RpcInfo.into_rpc())
        .build()
        .await?;

    if http {
        let url = format!("http://{}", rpc.http_address());
        let client = new_http_client(url, RpcAuthData::None).unwrap();
        let response: RpcClientResult<String> =
            client.request("example_server_protocol_version", rpc_params!()).await;
        assert_eq!(response.unwrap(), "version1");

        let response: RpcClientResult<String> =
            client.request("some_subsystem_name", rpc_params!()).await;
        assert_eq!(response.unwrap(), "sub1");

        let response: RpcClientResult<u64> =
            client.request("some_subsystem_add", rpc_params!(2, 5)).await;
        assert_eq!(response.unwrap(), 7);
    }

    subsystem::Subsystem::shutdown(rpc).await;
    Ok(())
}

async fn http_request(rpc: &Rpc, rpc_auth: RpcAuthData) -> anyhow::Result<()> {
    let url = format!("http://{}", rpc.http_address());
    let client = new_http_client(url, rpc_auth)?;
    let response: String = client.request("example_server_protocol_version", rpc_params!()).await?;
    anyhow::ensure!(response == "version1");
    Ok(())
}

fn gen_random_string(rng: &mut impl Rng, not_equal_to: &str) -> String {
    let len = rng.gen_range(1..20);
    loop {
        let val = Alphanumeric.sample_string(rng, len);
        if not_equal_to != val {
            return val;
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn rpc_server_auth_http(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let good_username = gen_random_string(&mut rng, "");
    let good_password = gen_random_string(&mut rng, "");
    let bad_username = gen_random_string(&mut rng, &good_username);
    let bad_password = gen_random_string(&mut rng, &good_password);

    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let data_dir: PathBuf = ".".into();
    let rpc = Builder::new(
        http_bind_address,
        Some(
            RpcCreds::new(
                &data_dir,
                Some(&good_username),
                Some(&good_password),
                Option::<String>::None,
            )
            .unwrap(),
        ),
    )
    .register(SubsystemRpcImpl.into_rpc())
    .register(RpcInfo.into_rpc())
    .build()
    .await
    .unwrap();

    // Valid requests
    http_request(
        &rpc,
        RpcAuthData::Basic {
            username: good_username.clone(),
            password: good_password.clone(),
        },
    )
    .await
    .unwrap();

    // Invalid requests
    http_request(&rpc, RpcAuthData::None).await.unwrap_err();

    http_request(
        &rpc,
        RpcAuthData::Basic {
            username: good_username.clone(),
            password: bad_password.clone(),
        },
    )
    .await
    .unwrap_err();
    http_request(
        &rpc,
        RpcAuthData::Basic {
            username: bad_username.clone(),
            password: good_password.clone(),
        },
    )
    .await
    .unwrap_err();

    subsystem::Subsystem::shutdown(rpc).await;
}

async fn ws_request(rpc: &Rpc, rpc_auth: RpcAuthData) -> anyhow::Result<()> {
    let url = format!("ws://{}", rpc.http_address());
    let client = new_ws_client(url, rpc_auth).await?;
    let response: String = client.request("example_server_protocol_version", rpc_params!()).await?;
    anyhow::ensure!(response == "version1");
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn rpc_server_auth_ws(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let good_username = gen_random_string(&mut rng, "");
    let good_password = gen_random_string(&mut rng, "");
    let bad_username = gen_random_string(&mut rng, &good_username);
    let bad_password = gen_random_string(&mut rng, &good_password);

    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let data_dir: PathBuf = ".".into();
    let rpc = Builder::new(
        http_bind_address,
        Some(
            RpcCreds::new(
                &data_dir,
                Some(&good_username),
                Some(&good_password),
                Option::<String>::None,
            )
            .unwrap(),
        ),
    )
    .register(SubsystemRpcImpl.into_rpc())
    .register(RpcInfo.into_rpc())
    .build()
    .await
    .unwrap();

    // Valid requests
    ws_request(
        &rpc,
        RpcAuthData::Basic {
            username: good_username.clone(),
            password: good_password.clone(),
        },
    )
    .await
    .unwrap();

    // Invalid requests
    ws_request(&rpc, RpcAuthData::None).await.unwrap_err();

    ws_request(
        &rpc,
        RpcAuthData::Basic {
            username: good_username.clone(),
            password: bad_password.clone(),
        },
    )
    .await
    .unwrap_err();
    ws_request(
        &rpc,
        RpcAuthData::Basic {
            username: bad_username.clone(),
            password: good_password.clone(),
        },
    )
    .await
    .unwrap_err();

    subsystem::Subsystem::shutdown(rpc).await;
}
