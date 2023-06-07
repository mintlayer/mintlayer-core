use std::convert::Infallible as Never;

use futures::Future;
use tokio::sync::oneshot;

use crate::peer_manager::peerdb::storage::PeerDbStorage;
use crate::Result;

pub async fn run_p2p<S>() -> Result<()>
where
    S: PeerDbStorage,
{
    unimplemented!()
}

type CancelOnDrop = oneshot::Sender<Never>;

async fn cancellable<Fut, Ret>(run: Fut) -> (impl Future<Output = Option<Ret>>, CancelOnDrop)
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
