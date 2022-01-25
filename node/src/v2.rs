use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// Definitions
struct Transaction;
struct Subsystem1 {
    block_counter: u64,
    block_hash: Vec<u128>,
}
struct Subsystem2 {
    tx_count: u32,
    mempool: Vec<u128>,
}

trait Launch {
    fn init(tx: mpsc::Sender<&'static str>) -> JoinHandle<()>;
    fn call<T>(func: impl Fn(T) -> T);
}

// Implementation of Subsystem1
impl Subsystem1 {
    pub fn init(tx: mpsc::Sender<&'static str>) -> JoinHandle<()> {
        task::spawn(async move {
            tx.send("Init Subsystem1 Thread").await;
            sleep(Duration::from_millis(200)).await;
        })
    }

    pub fn add_block(/*&mut self, */ hash: &u128) -> Result<(), Box<dyn std::error::Error>> {
        /*
        self.block_counter += 1;
        self.block_hash.push(*hash);
        println!("Hash {} added as block num {}", *hash, self.block_counter);
        */
        println!("Hash {} added as block num {}", 1, 2);
        Ok(())
    }
}

impl Launch for Subsystem1 {
    fn init(tx: mpsc::Sender<&'static str>) -> JoinHandle<()> {
        Subsystem1::init(tx)
    }

    fn call<T>(func: impl Fn(T) -> T) {}
}

// Implementation of Subsystem2
impl Subsystem2 {
    pub fn init(tx: mpsc::Sender<&'static str>) -> JoinHandle<()> {
        task::spawn(async move {
            tx.send("Init Subsystem2 Thread").await;
            sleep(Duration::from_millis(100)).await;
        })
    }

    pub fn submit_transaction(
        &self,
        tx: &Transaction,
        timestamp: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!();
    }
}

impl Launch for Subsystem2 {
    fn init(tx: mpsc::Sender<&'static str>) -> JoinHandle<()> {
        Subsystem2::init(tx)
    }

    fn call<T>(func: impl Fn(T) -> T) {}
}

// Implement Wrapper

struct Wrap;

impl Wrap {
    fn new<T: Launch>(tx: mpsc::Sender<&'static str>) -> JoinHandle<()> {
        T::init(tx)
    }
}

#[tokio::main]
async fn main() {
    let hash = 0;
    let value = 0x55566666;

    // Channels
    let (tx1, mut rx) = mpsc::channel(32);
    let tx2 = tx1.clone();
    tx1.abc();

    // Subsystem Initialization
    let wrap_sys1 = Wrap::new::<Subsystem1>(tx1);
    let wrap_sys2 = Wrap::new::<Subsystem2>(tx2);

    wrap_sys1.await;
    wrap_sys2.await;

    while let Some(message) = rx.recv().await {
        println!("GOT = {}", message);
    }

    // Subsystem Call
    //let result1 = wrap_sys1.call::<Subsystem1>(&Subsystem1::add_block, hash);
    //let result2 = wrap_sys1.call::<Subsystem2>(&Subsystem2::submit_transaction, value);
}
