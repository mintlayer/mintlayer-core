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

use super::*;

#[rstest]
#[trace]
#[tokio::test]
async fn invalid_query_parameter() {
    let (task, response) = spawn_webserver("/api/v1/feerate?in_top_x_mb=invalid").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Invalid in top X MB query parameter"
    );

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let in_top_x_mb = rng.gen_range(0..100);

    let (task, response) =
        spawn_webserver(&format!("/api/v1/feerate?in_top_x_mb={in_top_x_mb}")).await;

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    assert_eq!(body, format!("\"{in_top_x_mb}\""));

    task.abort();
}
