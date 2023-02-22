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

macro_rules! tests {
    ($($(#[$meta:meta])* $name:ident,)+) => {
        pub fn tests<T, N, A>() -> impl Iterator<Item = libtest_mimic::Trial>
        where
            T: p2p::testing_utils::TestTransportMaker<Transport = N::Transport, Address = N::Address>,
            N: p2p::net::NetworkingService + std::fmt::Debug + 'static,
            N::ConnectivityHandle: p2p::net::ConnectivityService<N> + std::fmt::Debug,
            N::SyncingMessagingHandle: p2p::net::SyncingMessagingService<N> + std::fmt::Debug,
            A: p2p::testing_utils::RandomAddressMaker<Address = N::Address>,
        {
            [
                $($(#[$meta])*
                libtest_mimic::Trial::test(
                concat!(module_path!(), "::", stringify!($name)),
                || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async {
                            $name::<T, N, A>().await;
                        });
                    Ok(())
                }
            ),)*].into_iter()
        }
    }
}
