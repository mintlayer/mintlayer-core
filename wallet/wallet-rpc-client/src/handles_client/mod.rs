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

use std::{collections::BTreeMap, fmt::Debug, num::NonZeroUsize, path::PathBuf, str::FromStr};

use chainstate::{rpc::RpcOutputValueIn, ChainInfo};
use common::{
    address::{dehexify::dehexify_all_addresses, AddressError},
    chain::{
        block::timestamp::BlockTimestamp, tokens::IsTokenUnfreezable, Block, GenBlock,
        SignedTransaction, SignedTransactionIntent, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, DecimalAmount, Id, Idable, H256},
};
use crypto::key::{hdkd::u31::U31, PrivateKey};
use node_comm::node_traits::NodeInterface;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use rpc::types::RpcHexString;
use serialization::{hex::HexEncode, hex_encoded::HexEncoded, json_encoded::JsonEncoded};
use utils_networking::IpOrSocketAddress;
use wallet::{account::TxInfo, version::get_version};
use wallet_controller::{
    types::{
        CreatedBlockInfo, GenericTokenTransfer, SeedWithPassPhrase, WalletCreationOptions,
        WalletInfo, WalletTypeArgs,
    },
    ConnectedPeer, ControllerConfig, UtxoState, UtxoType,
};
use wallet_rpc_lib::{
    types::{
        AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, ComposedTransaction, CreatedWallet,
        DelegationInfo, HardwareWalletType, LegacyVrfPublicKeyInfo, NewAccountInfo,
        NewDelegationTransaction, NewOrderTransaction, NewSubmittedTransaction,
        NewTokenTransaction, NftMetadata, NodeVersion, OpenedWallet, PoolInfo, PublicKeyInfo,
        RpcHashedTimelockContract, RpcInspectTransaction, RpcNewTransaction,
        RpcStandaloneAddresses, SendTokensFromMultisigAddressResult, StakePoolBalance,
        StakingStatus, StandaloneAddressWithDetails, TokenMetadata, TxOptionsOverrides, UtxoInfo,
        VrfPublicKeyInfo,
    },
    RpcError, WalletRpc,
};
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, scan_blockchain::ScanBlockchain,
    signature_status::SignatureStatus, utxo_types::UtxoTypes, with_locked::WithLocked,
};

use crate::wallet_rpc_traits::{
    FromRpcInput, PartialOrSignedTx, SignRawTransactionResult, WalletInterface,
};

pub struct WalletRpcHandlesClient<N: Clone> {
    wallet_rpc: WalletRpc<N>,
    server_rpc: Option<rpc::Rpc>,
}

#[derive(thiserror::Error, Debug)]
pub enum WalletRpcHandlesClientError<N: NodeInterface> {
    #[error(transparent)]
    WalletRpcError(#[from] wallet_rpc_lib::RpcError<N>),

    #[error(transparent)]
    SerializationError(#[from] serde_json::Error),

    #[error(transparent)]
    HexEncodingError(#[from] hex::FromHexError),

    #[error(transparent)]
    AddressError(#[from] AddressError),
}

impl<N> WalletRpcHandlesClient<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static + Debug,
{
    pub fn new(wallet_rpc: WalletRpc<N>, server_rpc: Option<rpc::Rpc>) -> Self {
        Self {
            wallet_rpc,
            server_rpc,
        }
    }
}

#[async_trait::async_trait]
impl<N> WalletInterface for WalletRpcHandlesClient<N>
where
    N: NodeInterface + Clone + Send + Sync + 'static + Debug,
{
    type Error = WalletRpcHandlesClientError<N>;

    async fn exit(&mut self) -> Result<(), Self::Error> {
        if let Some(rpc) = self.server_rpc.take() {
            rpc.shutdown().await;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        if let Some(rpc) = self.server_rpc.take() {
            rpc.shutdown().await;
        }
        Ok(())
    }

    async fn version(&self) -> Result<String, Self::Error> {
        Ok(get_version())
    }

    async fn rpc_completed(&self) {
        self.wallet_rpc.closed().await
    }

    async fn create_wallet(
        &self,
        path: PathBuf,
        wallet_args: WalletTypeArgs,
    ) -> Result<CreatedWallet, Self::Error> {
        let options = WalletCreationOptions {
            overwrite_wallet_file: false,
            scan_blockchain: ScanBlockchain::SkipScanning,
        };
        self.wallet_rpc
            .create_wallet(path, wallet_args, options)
            .await
            .map(Into::into)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn recover_wallet(
        &self,
        path: PathBuf,
        wallet_args: WalletTypeArgs,
    ) -> Result<CreatedWallet, Self::Error> {
        let options = WalletCreationOptions {
            overwrite_wallet_file: false,
            scan_blockchain: ScanBlockchain::ScanAndWait,
        };
        self.wallet_rpc
            .create_wallet(path, wallet_args, options)
            .await
            .map(Into::into)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn open_wallet(
        &self,
        path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> Result<OpenedWallet, Self::Error> {
        self.wallet_rpc
            .open_wallet(
                path,
                password,
                force_migrate_wallet_type.unwrap_or(false),
                ScanBlockchain::ScanAndWait,
                hardware_wallet,
            )
            .await
            .map(Into::into)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn close_wallet(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .close_wallet()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn wallet_info(&self) -> Result<WalletInfo, Self::Error> {
        self.wallet_rpc
            .wallet_info()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .sync()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn rescan(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .rescan()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        self.wallet_rpc
            .get_seed_phrase()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn purge_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        self.wallet_rpc
            .purge_seed_phrase()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .set_lookahead_size(lookahead_size, i_know_what_i_am_doing)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .encrypt_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_private_key_encryption()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unlock_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .lock_private_keys()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn best_block(&self) -> Result<BlockInfo, Self::Error> {
        self.wallet_rpc
            .best_block()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error> {
        self.wallet_rpc
            .create_account(name)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn rename_account(
        &self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<NewAccountInfo, Self::Error> {
        self.wallet_rpc
            .update_account_name(account_index, name)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn standalone_address_label_rename(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .standalone_address_label_rename(account_index, address.into(), label)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_standalone_address(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_standalone_watch_only_address(account_index, address.into(), label, no_rescan)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_standalone_private_key(
        &self,
        account_index: U31,
        private_key: HexEncoded<PrivateKey>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_standalone_private_key(account_index, private_key.take(), label, no_rescan)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_standalone_multisig(
        &self,
        account_index: U31,
        min_required_signatures: u8,
        public_keys: Vec<String>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .add_standalone_multisig(
                account_index,
                min_required_signatures,
                public_keys.into_iter().map(Into::into).collect(),
                label,
                no_rescan,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_issued_addresses(
        &self,
        account_index: U31,
        include_change_addresses: bool,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error> {
        self.wallet_rpc
            .get_issued_addresses(account_index, include_change_addresses)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_standalone_addresses(
        &self,
        account_index: U31,
    ) -> Result<RpcStandaloneAddresses, Self::Error> {
        self.wallet_rpc
            .get_standalone_addresses(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_standalone_address_details(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<StandaloneAddressWithDetails, Self::Error> {
        self.wallet_rpc
            .get_standalone_address_details(account_index, address.into())
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_address(&self, account_index: U31) -> Result<AddressInfo, Self::Error> {
        self.wallet_rpc
            .issue_address(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reveal_public_key(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .find_public_key(account_index, address.into())
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_balance(
        &self,
        account_index: U31,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error> {
        self.wallet_rpc
            .get_balance(
                account_index,
                (&utxo_states).try_into().unwrap_or(UtxoState::Confirmed.into()),
                with_locked,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_multisig_utxos(
        &self,
        account_index: U31,
        utxo_types: Vec<UtxoType>,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Vec<UtxoInfo>, Self::Error> {
        let utxos = self
            .wallet_rpc
            .get_multisig_utxos(
                account_index,
                (&utxo_types).try_into().unwrap_or(UtxoTypes::ALL),
                (&utxo_states).try_into().unwrap_or(UtxoState::Confirmed.into()),
                with_locked,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)?;

        utxos
            .into_iter()
            .map(|(utxo_outpoint, tx_ouput)| {
                UtxoInfo::new(utxo_outpoint, tx_ouput, self.wallet_rpc.chain_config())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(WalletRpcHandlesClientError::AddressError)
    }

    async fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: Vec<UtxoType>,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Vec<UtxoInfo>, Self::Error> {
        let utxos = self
            .wallet_rpc
            .get_utxos(
                account_index,
                (&utxo_types).try_into().unwrap_or(UtxoTypes::ALL),
                (&utxo_states).try_into().unwrap_or(UtxoState::Confirmed.into()),
                with_locked,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)?;

        utxos
            .into_iter()
            .map(|(utxo_outpoint, tx_ouput)| {
                UtxoInfo::new(utxo_outpoint, tx_ouput, self.wallet_rpc.chain_config())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(WalletRpcHandlesClientError::AddressError)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> Result<NewSubmittedTransaction, Self::Error> {
        self.wallet_rpc
            .submit_raw_transaction(tx, do_not_store, options)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sign_challenge(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .sign_challenge(account_index, challenge.into_bytes(), address.into())
            .await
            .map(|result| result.to_hex())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn transaction_from_cold_input(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxo: UtxoOutPoint,
        change_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<ComposedTransaction, Self::Error> {
        self.wallet_rpc
            .request_send_coins(
                account_index,
                address.into(),
                amount.into(),
                selected_utxo,
                change_address.map(Into::into),
                config,
            )
            .await
            .map(|(tx, fees)| ComposedTransaction {
                hex: HexEncoded::new(tx).to_string(),
                fees,
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn transaction_inspect(
        &self,
        transaction: String,
    ) -> Result<RpcInspectTransaction, Self::Error> {
        self.wallet_rpc
            .transaction_inspect(RpcHexString::from_str(&transaction)?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(Into::into)
    }

    async fn sign_challenge_hex(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        let challenge = hex::decode(challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .sign_challenge(account_index, challenge, address.into())
            .await
            .map(|result| result.to_hex())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        let signed_challenge =
            hex::decode(signed_challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .verify_challenge(message.into_bytes(), signed_challenge, address.into())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn verify_challenge_hex(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        let message = hex::decode(message).map_err(|_| RpcError::<N>::InvalidHexData)?;
        let signed_challenge =
            hex::decode(signed_challenge).map_err(|_| RpcError::<N>::InvalidHexData)?;
        self.wallet_rpc
            .verify_challenge(message, signed_challenge, address.into())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<String>>>,
        only_transaction: bool,
    ) -> Result<ComposedTransaction, Self::Error> {
        let inputs = inputs.into_iter().map(Into::into).collect();
        let htlc_secrets = htlc_secrets
            .map(|s| s.into_iter().map(|s| s.map(|s| s.parse()).transpose()).collect())
            .transpose()?;
        self.wallet_rpc
            .compose_transaction(inputs, outputs, htlc_secrets, only_transaction)
            .await
            .map(|(tx, fees)| ComposedTransaction {
                hex: tx.to_hex(),
                fees,
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_coins(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .send_coins(
                account_index,
                address.into(),
                amount.into(),
                selected_utxos,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(RpcNewTransaction::new)
    }

    async fn sweep_addresses(
        &self,
        account_index: U31,
        destination_address: String,
        from_addresses: Vec<String>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .sweep_addresses(
                account_index,
                destination_address.into(),
                from_addresses.into_iter().map(Into::into).collect(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sweep_delegation(
        &self,
        account_index: U31,
        destination_address: String,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .sweep_delegation(
                account_index,
                destination_address.into(),
                delegation_id.into(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        staker_address: Option<String>,
        vrf_public_key: Option<String>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .create_stake_pool(
                account_index,
                amount.into(),
                cost_per_block.into(),
                margin_ratio_per_thousand,
                decommission_address.into(),
                staker_address.map(Into::into),
                vrf_public_key.map(Into::into),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(RpcNewTransaction::new)
    }

    async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .decommission_stake_pool(
                account_index,
                pool_id.into(),
                output_address.map(Into::into),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(RpcNewTransaction::new)
    }

    async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<HexEncoded<PartiallySignedTransaction>, Self::Error> {
        self.wallet_rpc
            .decommission_stake_pool_request(
                account_index,
                pool_id.into(),
                output_address.map(Into::into),
                config,
            )
            .await
            .map(HexEncoded::new)
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_delegation(
        &self,
        account_index: U31,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegationTransaction, Self::Error> {
        self.wallet_rpc
            .create_delegation(account_index, address.into(), pool_id.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(|(tx, delegation_id)| NewDelegationTransaction::new(tx, delegation_id))
    }

    async fn delegate_staking(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .delegate_staking(account_index, amount.into(), delegation_id.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(RpcNewTransaction::new)
    }

    async fn withdraw_from_delegation(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .withdraw_from_delegation(
                account_index,
                address.into(),
                amount.into(),
                delegation_id.into(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(RpcNewTransaction::new)
    }

    async fn start_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        self.wallet_rpc
            .start_staking(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stop_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        self.wallet_rpc
            .stop_staking(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn staking_status(&self, account_index: U31) -> Result<StakingStatus, Self::Error> {
        self.wallet_rpc
            .staking_status(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_staking_pools(&self, account_index: U31) -> Result<Vec<PoolInfo>, Self::Error> {
        self.wallet_rpc
            .list_staking_pools(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pools_for_decommission(
        &self,
        account_index: U31,
    ) -> Result<Vec<PoolInfo>, Self::Error> {
        self.wallet_rpc
            .list_pools_for_decommission(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error> {
        self.wallet_rpc
            .stake_pool_balance(pool_id.into())
            .await
            .map(|balance| StakePoolBalance { balance })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_delegation_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<DelegationInfo>, Self::Error> {
        self.wallet_rpc
            .list_delegation_ids(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<CreatedBlockInfo>, Self::Error> {
        self.wallet_rpc
            .list_created_blocks_ids(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn new_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<VrfPublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .issue_vrf_key(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error> {
        self.wallet_rpc
            .get_vrf_key_usage(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<LegacyVrfPublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .get_legacy_vrf_public_key(account_index)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_nft(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<NewTokenTransaction, Self::Error> {
        self.wallet_rpc
            .issue_new_nft(
                account_index,
                destination_address.into(),
                metadata.into_metadata(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_token(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<NewTokenTransaction, Self::Error> {
        let token_supply = metadata.token_supply()?;
        let is_freezable = metadata.is_freezable();
        self.wallet_rpc
            .issue_new_token(
                account_index,
                metadata.number_of_decimals,
                destination_address.into(),
                metadata.token_ticker.into_bytes(),
                metadata.metadata_uri.into_bytes(),
                token_supply,
                is_freezable,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .change_token_authority(account_index, token_id.into(), address.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn change_token_metadata_uri(
        &self,
        account_index: U31,
        token_id: String,
        metadata_uri: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .change_token_metadata_uri(
                account_index,
                token_id.into(),
                RpcHexString::from_str(&metadata_uri)?,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .mint_tokens(
                account_index,
                token_id.into(),
                address.into(),
                amount.into(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .unmint_tokens(account_index, token_id.into(), amount.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .lock_token_supply(account_index, token_id.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn freeze_token(
        &self,
        account_index: U31,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        let is_unfreezable = if is_unfreezable {
            IsTokenUnfreezable::Yes
        } else {
            IsTokenUnfreezable::No
        };
        self.wallet_rpc
            .freeze_token(account_index, token_id.into(), is_unfreezable, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .unfreeze_token(account_index, token_id.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .send_tokens(
                account_index,
                token_id.into(),
                address.into(),
                amount.into(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn make_tx_for_sending_tokens_with_intent(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        intent: String,
        config: ControllerConfig,
    ) -> Result<
        (
            HexEncoded<SignedTransaction>,
            HexEncoded<SignedTransactionIntent>,
        ),
        Self::Error,
    > {
        self.wallet_rpc
            .create_transaction_for_sending_tokens_with_intent(
                account_index,
                token_id.into(),
                address.into(),
                amount.into(),
                intent,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .map(|(tx, intent)| (HexEncoded::new(tx.tx), HexEncoded::new(intent)))
    }

    async fn make_tx_to_send_tokens_from_multisig_address(
        &self,
        account_index: U31,
        from_address: String,
        fee_change_address: Option<String>,
        outputs: Vec<GenericTokenTransfer>,
        config: ControllerConfig,
    ) -> Result<SendTokensFromMultisigAddressResult, Self::Error> {
        self.wallet_rpc
            .make_tx_to_send_tokens_from_multisig_address(
                account_index,
                from_address.into(),
                fee_change_address.map(Into::into),
                outputs,
                config,
            )
            .await
            .map(
                |(tx, cur_signatures, fees)| SendTokensFromMultisigAddressResult {
                    transaction: HexEncoded::new(tx),
                    current_signatures: cur_signatures.into_iter().map(Into::into).collect(),
                    fees,
                },
            )
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn deposit_data(
        &self,
        account_index: U31,
        data: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        let data = hex::decode(data).map_err(|_| RpcError::<N>::InvalidHexData)?;

        self.wallet_rpc
            .deposit_data(account_index, data, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_htlc_transaction(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        token_id: Option<String>,
        htlc: RpcHashedTimelockContract,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .create_htlc_transaction(
                account_index,
                amount.into(),
                token_id.map(|id| id.into()),
                htlc,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_order(
        &self,
        account_index: U31,
        ask_token_id: Option<String>,
        ask_amount: DecimalAmount,
        give_token_id: Option<String>,
        give_amount: DecimalAmount,
        conclude_address: String,
        config: ControllerConfig,
    ) -> Result<NewOrderTransaction, Self::Error> {
        self.wallet_rpc
            .create_order(
                account_index,
                RpcOutputValueIn::from_rpc_string_input(ask_token_id, ask_amount),
                RpcOutputValueIn::from_rpc_string_input(give_token_id, give_amount),
                conclude_address.into(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn conclude_order(
        &self,
        account_index: U31,
        order_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .conclude_order(
                account_index,
                order_id.into(),
                output_address.map(|addr| addr.into()),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn fill_order(
        &self,
        account_index: U31,
        order_id: String,
        fill_amount_in_ask_currency: DecimalAmount,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .fill_order(
                account_index,
                order_id.into(),
                fill_amount_in_ask_currency.into(),
                output_address.map(|addr| addr.into()),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn freeze_order(
        &self,
        account_index: U31,
        order_id: String,
        config: ControllerConfig,
    ) -> Result<RpcNewTransaction, Self::Error> {
        self.wallet_rpc
            .freeze_order(account_index, order_id.into(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_version(&self) -> Result<NodeVersion, Self::Error> {
        self.wallet_rpc
            .node_version()
            .await
            .map(|version| NodeVersion { version })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .node_shutdown()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error> {
        self.wallet_rpc
            .node_enable_networking(enable)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .connect_to_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn disconnect_peer(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        self.wallet_rpc
            .disconnect_peer(peer_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_banned(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_banned()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .ban_address(address, duration)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unban_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unban_address(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_discouraged(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_discouraged()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn undiscourage_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .undiscourage_address(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn peer_count(&self) -> Result<usize, Self::Error> {
        self.wallet_rpc
            .peer_count()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        self.wallet_rpc
            .connected_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reserved_peers(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        self.wallet_rpc
            .reserved_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> Result<(), Self::Error> {
        self.wallet_rpc
            .submit_block(block)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        self.wallet_rpc
            .chainstate_info()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn abandon_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .abandon_transaction(account_index, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pending_transactions(
        &self,
        account_index: U31,
    ) -> Result<Vec<Id<Transaction>>, Self::Error> {
        self.wallet_rpc
            .pending_transactions(account_index)
            .await
            .map(|txs| txs.into_iter().map(|tx| tx.get_id()).collect::<Vec<_>>())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_transactions_by_address(
        &self,
        account_index: U31,
        address: Option<String>,
        limit: usize,
    ) -> Result<Vec<TxInfo>, Self::Error> {
        self.wallet_rpc
            .mainchain_transactions(account_index, address.map(Into::into), limit)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .and_then(|tx| {
                let str = JsonEncoded::new((tx.get_transaction(), tx.state())).to_string();
                let str = dehexify_all_addresses(self.wallet_rpc.chain_config(), &str);
                serde_json::from_str::<serde_json::Value>(&str)
                    .map_err(WalletRpcHandlesClientError::SerializationError)
            })
    }

    async fn get_raw_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_signed_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: String,
        config: ControllerConfig,
    ) -> Result<SignRawTransactionResult, Self::Error> {
        self.wallet_rpc
            .sign_raw_transaction(account_index, RpcHexString::from_str(&raw_tx)?, config)
            .await
            .map(|(ptx, prev_signatures, cur_signatures)| {
                let is_fully_signed = ptx.all_signatures_available()
                    && cur_signatures.iter().all(|s| *s == SignatureStatus::FullySigned);

                let tx = if is_fully_signed {
                    PartialOrSignedTx::Signed(ptx.into_signed_tx().expect("already checked2"))
                } else {
                    PartialOrSignedTx::Partial(ptx)
                };
                let previous_signatures = prev_signatures.into_iter().map(Into::into).collect();
                let current_signatures = cur_signatures.into_iter().map(Into::into).collect();

                SignRawTransactionResult {
                    transaction: tx,
                    previous_signatures,
                    current_signatures,
                }
            })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.wallet_rpc
            .node_best_block_id()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet_rpc
            .node_best_block_height()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        self.wallet_rpc
            .node_block_id(block_height)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_generate_block(
        &self,
        account_index: U31,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .generate_block(
                account_index,
                transactions.into_iter().map(HexEncoded::take).collect(),
            )
            .await
            .map(|_| ())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_generate_blocks(
        &self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .generate_blocks(account_index, block_count)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_find_timestamps_for_staking(
        &self,
        pool_id: String,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, Self::Error> {
        self.wallet_rpc
            .find_timestamps_for_staking(
                pool_id.into(),
                min_height,
                max_height,
                seconds_to_check_for_height,
                check_all_timestamps_between_blocks,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_block(&self, block_id: String) -> Result<Option<String>, Self::Error> {
        let hash = H256::from_str(&block_id).map_err(|_| RpcError::<N>::InvalidBlockId)?;
        self.wallet_rpc
            .get_node_block(hash.into())
            .await
            .map(|block_opt| block_opt.map(|block| block.hex_encode()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        self.wallet_rpc
            .node_get_block_ids_as_checkpoints(start_height, end_height, step)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }
}
