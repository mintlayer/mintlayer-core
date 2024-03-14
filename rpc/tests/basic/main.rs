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

use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use crypto::random::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::rpc_params;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use rpc::{
    new_http_client, new_ws_client, rpc_creds::RpcCreds, subscription, Builder, Rpc, RpcAuthData,
    RpcClientResult, RpcResult,
};

mod desc;

#[rpc::describe]
#[rpc::rpc(server, namespace = "some_subsystem")]
pub trait SubsystemRpc {
    #[method(name = "name")]
    fn name(&self) -> RpcResult<String>;

    #[method(name = "add")]
    fn add(&self, a: u64, b: u64) -> RpcResult<u64>;

    #[subscription(name = "subscribe_squares", item = u32)]
    async fn subscribe_squares(&self) -> subscription::Reply;

    #[method(name = "convoluted")]
    fn convoluted(
        &self,
        first: Option<bool>,
        second: (String, u64, Option<usize>),
        third: BTreeMap<String, std::time::Duration>,
    ) -> RpcResult<Vec<String>>;
}

#[rpc::rpc(server, namespace = "example_server")]
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

#[async_trait::async_trait]
impl SubsystemRpcServer for SubsystemRpcImpl {
    fn name(&self) -> RpcResult<String> {
        Ok("sub1".into())
    }

    fn add(&self, a: u64, b: u64) -> RpcResult<u64> {
        Ok(a + b)
    }

    async fn subscribe_squares(&self, pending: subscription::Pending) -> subscription::Reply {
        let sub = subscription::accept::<u32>(pending).await?;
        for i in 1u32..(1u32 << 16) {
            sub.send(&(i * i)).await?;
        }
        Ok(())
    }

    fn convoluted(
        &self,
        _first: Option<bool>,
        _second: (String, u64, Option<usize>),
        _third: BTreeMap<String, std::time::Duration>,
    ) -> RpcResult<Vec<String>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn method_list() -> anyhow::Result<()> {
    const METHOD_LIST: [&str; 6] = [
        "method_list",
        "some_subsystem_add",
        "some_subsystem_convoluted",
        "some_subsystem_name",
        "some_subsystem_subscribe_squares",
        "some_subsystem_unsubscribe_squares",
    ];

    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    let rpc = Builder::new(http_bind_address, None)
        .with_method_list("method_list")
        .register(SubsystemRpcImpl.into_rpc())
        .build()
        .await?;

    let url = format!("http://{}", rpc.http_address());
    let client = new_http_client(url, RpcAuthData::None).unwrap();
    let response: RpcClientResult<Vec<String>> = client.request("method_list", [(); 0]).await;
    assert_eq!(response.unwrap(), METHOD_LIST);

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

fn assert_unauthorized(result: anyhow::Result<()>) {
    let error = result.expect_err("Expected error, got success");
    // We can't test for much more because apparently every different system is returning a different message,
    // but the common thing between them all is the status code "401"
    assert!(error.to_string().contains("401"));
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
    assert_unauthorized(http_request(&rpc, RpcAuthData::None).await);

    assert_unauthorized(
        http_request(
            &rpc,
            RpcAuthData::Basic {
                username: good_username.clone(),
                password: bad_password.clone(),
            },
        )
        .await,
    );
    assert_unauthorized(
        http_request(
            &rpc,
            RpcAuthData::Basic {
                username: bad_username.clone(),
                password: good_password.clone(),
            },
        )
        .await,
    );

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
    assert_unauthorized(ws_request(&rpc, RpcAuthData::None).await);

    assert_unauthorized(
        ws_request(
            &rpc,
            RpcAuthData::Basic {
                username: good_username.clone(),
                password: bad_password.clone(),
            },
        )
        .await,
    );
    assert_unauthorized(
        ws_request(
            &rpc,
            RpcAuthData::Basic {
                username: bad_username.clone(),
                password: good_password.clone(),
            },
        )
        .await,
    );

    subsystem::Subsystem::shutdown(rpc).await;
}

#[tokio::test]
async fn simple_subscription() -> anyhow::Result<()> {
    let bind_address = "127.0.0.1:0".parse::<SocketAddr>()?;

    let rpc = Builder::new(bind_address, None)
        .register(SubsystemRpcImpl.into_rpc())
        .build()
        .await?;

    let url = format!("ws://{}", rpc.http_address());
    let client = new_ws_client(url, RpcAuthData::None).await?;

    let mut squares_sub: jsonrpsee::core::client::Subscription<u32> = client
        .subscribe(
            "some_subsystem_subscribe_squares",
            [(); 0],
            "some_subsystem_unsubscribe_squares",
        )
        .await?;

    assert_eq!(squares_sub.next().await.unwrap()?, 1);
    assert_eq!(squares_sub.next().await.unwrap()?, 4);
    assert_eq!(squares_sub.next().await.unwrap()?, 9);

    squares_sub.unsubscribe().await.unwrap();

    subsystem::Subsystem::shutdown(rpc).await;
    Ok(())
}
