use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chainstate::chainstate_interface;
use common::chain::{ChainConfig, SignedTransaction};
use common::primitives::Idable;
use common::time_getter::TimeGetter;
use futures::future::BoxFuture;
use futures::FutureExt;
use mempool::MempoolHandle;

use logging::log;
use subsystem::CallRequest;
use tokio::sync::mpsc;

use crate::config::P2pConfig;
use crate::error::{ConversionError, P2pError};
use crate::interface::p2p_interface::P2pInterface;
use crate::interface::types::ConnectedPeer;
use crate::message::SyncMessage;
use crate::net::{ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver};
use crate::peer_manager::peerdb::storage::PeerDbStorage;
use crate::peer_manager::PeerManager;
use crate::types::peer_id::PeerId;
use crate::utils::oneshot_nofail;
use crate::{sync, P2pEventHandler, PeerManagerEvent};
use crate::{P2pEvent, Result};

pub type ChainstateHandle = subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>;

#[allow(clippy::too_many_arguments)]
pub async fn run_p2p<'a, N, S>(
    transport: N::Transport,
    bind_addresses: Vec<N::Address>,
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,

    p2p_call: CallRequest<dyn P2pInterface>,
    shutdown_request: impl Future<Output = impl Send + 'a> + Send + 'a,
) -> Result<impl Future<Output = ()> + 'a>
where
    N: NetworkingService,
    N: 'static, // this bound should be revised

    S: PeerDbStorage,
    S: 'a,

    N::ConnectivityHandle: ConnectivityService<N>,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
{
    log::warn!("run-p2p N: {}", std::any::type_name::<N>());

    let (netsvc_shutdown_tx, netsvc_shutdown_rx) = utils::graceful_shutdown_chan();
    let (p2p_event_handlers_tx, p2p_event_handlers_rx) = mpsc::unbounded_channel();
    let (connectivity_handle, messaging_handle, sync_event_receiver, netsvc_running) = N::start(
        transport,
        bind_addresses,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        netsvc_shutdown_rx,
        p2p_event_handlers_rx,
    )
    .await?;
    let netsvc_running = netsvc_running.map(Result::Ok).boxed();

    let (peer_manager_mbox_tx, peer_manager_mbox_rx) = mpsc::unbounded_channel();
    let mut peer_manager = PeerManager::<N, S>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_manager_mbox_rx,
        time_getter.clone(),
        peerdb_storage,
    )?;
    let (peer_manager_shutdown_tx, peer_manager_shutdown_rx) = utils::graceful_shutdown_chan();
    let peer_manager_running =
        async move { peer_manager.run(peer_manager_shutdown_rx).await }.boxed();

    let mut sync_manager = sync::BlockSyncManager::new(
        chain_config,
        p2p_config,
        messaging_handle.clone(),
        sync_event_receiver,
        chainstate_handle,
        mempool_handle.clone(),
        peer_manager_mbox_tx.clone(),
        time_getter,
    );
    let (sync_manager_shutdown_tx, sync_manager_shutdown_rx) = utils::graceful_shutdown_chan();
    let sync_manager_running =
        async move { sync_manager.run(sync_manager_shutdown_rx).await }.boxed();

    let p2p_subsys_running = p2p_interface_loop(
        messaging_handle,
        mempool_handle,
        p2p_event_handlers_tx,
        peer_manager_mbox_tx,
        p2p_call,
        shutdown_request,
    )
    .boxed();

    const NETSVC_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
    const PEER_MGR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
    const SYNC_MGR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

    let running = run_multiple(
        vec![netsvc_running, peer_manager_running, sync_manager_running, p2p_subsys_running],
        vec![
            Some((netsvc_shutdown_tx, NETSVC_SHUTDOWN_TIMEOUT)),
            Some((peer_manager_shutdown_tx, PEER_MGR_SHUTDOWN_TIMEOUT)),
            Some((sync_manager_shutdown_tx, SYNC_MGR_SHUTDOWN_TIMEOUT)),
            None,
        ],
    );

    Ok(running)
}

async fn p2p_interface_loop<T>(
    messaging_handle: T::MessagingHandle,
    mempool_handle: MempoolHandle,
    p2p_event_handlers_tx: mpsc::UnboundedSender<P2pEventHandler>,
    peer_manager_mbox_tx: mpsc::UnboundedSender<PeerManagerEvent<T>>,
    mut p2p_call: CallRequest<dyn P2pInterface>,
    shutdown_request: impl Future<Output = impl Send> + Send,
) -> Result<()>
where
    T: NetworkingService + 'static,
    T::MessagingHandle: MessagingService,
{
    let shutdown_request = shutdown_request.fuse();
    let mut shutdown_request = std::pin::pin!(shutdown_request);

    let mut p2p_interface = P2pInterfaceImpl {
        p2p_event_handlers_tx,
        messaging_handle,
        peer_manager_mbox_tx,
        mempool_handle,
    };

    loop {
        tokio::select! {
            _ = shutdown_request.as_mut() => {
                log::info!("Shutdown requested");
                p2p_call.close();
            },

            call_opt = p2p_call.recv_opt() => if let Some(call) = call_opt {
                call(&mut p2p_interface).await;
            } else {
                break
            }
        }
    }

    log::info!("Shutting down normally");

    Ok(())
}

struct P2pInterfaceImpl<T>
where
    T: NetworkingService,
{
    p2p_event_handlers_tx: mpsc::UnboundedSender<P2pEventHandler>,
    messaging_handle: T::MessagingHandle,
    peer_manager_mbox_tx: mpsc::UnboundedSender<PeerManagerEvent<T>>,
    mempool_handle: MempoolHandle,
}

#[async_trait::async_trait]
impl<T> P2pInterface for P2pInterfaceImpl<T>
where
    T: NetworkingService,
    T::MessagingHandle: MessagingService + Send + Sync,
{
    async fn connect(&mut self, addr: String) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::Connect(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();

        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::Disconnect(peer_id, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot_nofail::channel();
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::GetPeerCount(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<String>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::GetBindAddresses(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::GetConnectedPeers(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn add_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::AddReserved(addr))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }

    async fn remove_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.peer_manager_mbox_tx
            .send(PeerManagerEvent::RemoveReserved(addr))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }

    async fn submit_transaction(&mut self, tx: SignedTransaction) -> crate::Result<()> {
        let id = tx.transaction().get_id();
        self.mempool_handle.call_mut(|m| m.add_transaction(tx)).await??;
        self.messaging_handle.broadcast_message(SyncMessage::NewTransaction(id))
    }

    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(P2pEvent) + Send + Sync>,
    ) -> crate::Result<()> {
        self.p2p_event_handlers_tx.send(handler).map_err(Into::into)
    }
}

async fn run_multiple<S>(
    services: Vec<BoxFuture<'_, Result<()>>>,
    mut shutdown_switches: Vec<Option<(S, Duration)>>,
) {
    assert_eq!(services.len(), shutdown_switches.len());

    log::error!("run-multiple [len: {}]", services.len());

    let (outcome, idx, mut services) = futures::future::select_all(services).await;

    if let Err(reason) = outcome {
        log::warn!("Service[{}] shut down with error: {}", idx, reason);
    }

    services.truncate(idx);
    shutdown_switches.truncate(idx);

    shutdown_multiple(services, shutdown_switches).await
}

async fn shutdown_multiple<S>(
    mut services: Vec<BoxFuture<'_, Result<()>>>,
    mut shutdown_switches: Vec<Option<(S, Duration)>>,
) {
    loop {
        assert_eq!(services.len(), shutdown_switches.len());
        log::error!("shutdown-multiple [len: {}]", services.len());

        let Some(shutdown_kit) = shutdown_switches.pop() else {return};

        if let Some((tx, timeout)) = shutdown_kit {
            std::mem::drop(tx);

            let mut select_all = futures::future::select_all(services);
            match tokio::time::timeout(timeout, &mut select_all).await {
                Ok((outcome, idx, services_)) => {
                    if let Err(reason) = outcome {
                        log::warn!("Service[{}] shut down with error: {}", idx, reason);
                    }
                    services = services_;
                    services.truncate(idx);
                    shutdown_switches.truncate(idx);
                }
                Err(_timeout) => {
                    let idx = shutdown_switches.len();
                    log::warn!("Service[{}] timed out shutting down", idx);

                    services = select_all.into_inner();
                    let _ = services.pop();
                }
            }
        } else {
            services.pop();
        }
    }
}

mod utils {
    use std::future::Future;

    use futures::never::Never;
    use tokio::sync::oneshot;

    pub fn graceful_shutdown_chan() -> (impl Drop, impl Future<Output = impl Send> + Send) {
        oneshot::channel::<Never>()
    }
}
