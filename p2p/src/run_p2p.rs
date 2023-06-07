use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chainstate::chainstate_interface;
use common::chain::ChainConfig;
use common::time_getter::TimeGetter;
use futures::FutureExt;
use mempool::MempoolHandle;

use subsystem::CallRequest;
use tokio::sync::mpsc;

use crate::config::P2pConfig;
use crate::interface::p2p_interface::P2pInterface;
use crate::net::{ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver};
use crate::peer_manager::peerdb::storage::PeerDbStorage;
use crate::peer_manager::PeerManager;
use crate::{sync, P2pEventHandler};
use crate::Result;

pub type ChainstateHandle = subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>;

pub async fn run_p2p<N, S>(
    transport: N::Transport,
    bind_addresses: Vec<N::Address>,
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    peerdb_storage: S,

    p2p_call: CallRequest<dyn P2pInterface>,
) -> Result<()>
where
    N: NetworkingService,
    N: 'static, // this bound should be revised
    S: PeerDbStorage,

    N::ConnectivityHandle: ConnectivityService<N>,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
{
    let to_be_removed_shutting_down_flag = Arc::new(AtomicBool::new(false));

    let (netsvc_shutdown_tx, netsvc_shutdown_rx) = utils::graceful_shutdown_chan();
    let (p2p_event_handlers_tx, p2p_event_handlers_rx) = mpsc::unbounded_channel();
    let (connectivity_handle, messaging_handle, sync_event_receiver, netsvc_running) = N::start(
        transport,
        bind_addresses,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        to_be_removed_shutting_down_flag,
        netsvc_shutdown_rx,
        p2p_event_handlers_rx,
    )
    .await?;

    let (peer_manager_mbox_tx, peer_manager_mbox_rx) = mpsc::unbounded_channel();
    let mut peer_manager = PeerManager::<N, S>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_manager_mbox_rx,
        time_getter.clone(),
        peerdb_storage,
    )?;
    let peer_manager_running = peer_manager.run();
    
    let mut sync_manager = sync::BlockSyncManager::new(
        chain_config,
        p2p_config,
        messaging_handle,
        sync_event_receiver,
        chainstate_handle,
        mempool_handle,
        peer_manager_mbox_tx,
        time_getter,
    );
    let sync_manager_running = sync_manager.run();
    
    let p2p_subsys_running = p2p_interface_loop(
        p2p_event_handlers_tx
    );
    
    let components_running = [
        netsvc_running.boxed(),
        async move {
            if let Err(reason) = peer_manager_running.await {
                todo!("ew, peer-mgr... {:?}", reason)
            }
        }.boxed(),
        async move {
            if let Err(reason) = sync_manager_running.await {
                todo!("ew, sync-mgr... {:?}", reason)
            }
        }.boxed(),
        async move {
            if let Err(reason) = p2p_subsys_running.await {
                todo!("ew, p2p-subsys... {:?}", reason)
            }
        }.boxed(),
    ];

    let shutdown_txs = [
        Some(netsvc_shutdown_tx),
        None,
        None,
        None,
    ];

    assert_eq!(components_running.len(), shutdown_txs.len());

    run_sup(components_running, shutdown_txs).await
}

async fn p2p_interface_loop(p2p_event_handlers_tx: mpsc::UnboundedSender<P2pEventHandler>) -> Result<()> {
    unimplemented!()
}

mod utils {
    use std::convert::Infallible as Never;

    use futures::Future;
    use tokio::sync::oneshot;

    pub type CancelOnDrop = oneshot::Sender<Never>;

    pub fn graceful_shutdown_chan() -> (oneshot::Sender<()>, oneshot::Receiver<()>) {
        oneshot::channel()
    }

    pub async fn log_on_error<Fut, T, E>() -> ()
    {

    }
    

    pub fn cancellable<Fut, Ret>(
        run: Fut,
    ) -> (impl Future<Output = Option<Ret>>, CancelOnDrop)
    where
        Fut: Future<Output = Ret>,
    {
        let (tx, rx) = oneshot::channel();

        let select = async move {
            tokio::select! {
                done = run => { Some(done) },
                _cancelled = rx => { None },
            }
        };

        (select, tx)
    }
}
