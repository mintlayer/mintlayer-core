use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    thread,
};

struct Transaction;

struct Subsystem1 {
    block_counter: u64,
    block_hash: Vec<u128>,
}

struct Subsystem2 {
    tx_count: u32,
    mempool: Vec<u128>,
}

impl Subsystem1 {
    pub fn add_them(&self, x: i32, y: i32) -> i32 {
        x + y
    }

    pub fn add_block(&mut self, hash: &u128) -> Result<(), Box<dyn std::error::Error>> {
        self.block_counter += 1;
        self.block_hash.push(hash.clone());
        todo!()
    }

    /// Create a new Subsystem Future
    pub fn init() -> Self {
        let block_counter = 0;
        let block_hash: Vec<u128> = vec![0]; // GENESIS

        Subsystem1 {
            block_counter,
            block_hash,
        }
    }
}

impl Subsystem2 {
    pub fn submit_transaction(
        &mut self,
        tx: &Transaction,
        timestamp: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!();
    }

    /// Create a new Subsystem Future
    pub fn init() -> Self {
        let tx_count = 0;
        let mempool: Vec<u128> = vec![0]; // GENESIS

        Subsystem2 { tx_count, mempool }
    }
}

struct Wrap {
    sender: Sender<(for<'r> fn(&'r Subsystem1, i32, i32) -> i32, i32, i32)>,
    handle: JoinHandle<()>,
    result_rx: Receiver<i32>,
}

impl Wrap {
    fn Launch(func: fn() -> Subsystem1) -> Self {
        type F = (for<'r> fn(&'r Subsystem1, i32, i32) -> i32, i32, i32);

        let (tx, rx) = mpsc::channel::<F>();
        let (tx2, rx2) = mpsc::channel();

        let handle = thread::spawn(move || {
            // TODO SOMETHING HERER
            let instance = func();
            loop {
                let t = rx.recv().unwrap();
                let result = (t.0)(&instance, t.1, t.2);
                tx2.send(result).unwrap();
            }
        });

        Wrap {
            sender: tx,
            handle: handle,
            result_rx: rx2,
        }
    }
}

enum Subsystem1Callables {
    add_them((for<'r> fn(&'r Subsystem1, i32, i32) -> i32, i32, i32)),
    add_block(
        (
            for<'r> fn(&'r mut Subsystem1, &u128) -> Result<(), Box<dyn std::error::Error>>,
            u128,
        ),
    ),
    init,
    shutdown,
}

fn main() {
    // create a thread in each Subsystem and return a future
    let wrapper_s1 = Wrap::Launch(Subsystem1::init);

    let hash = 0;

    // Channels
    wrapper_s1
        .sender
        .send((Subsystem1::add_them, 3, 4))
        .unwrap();

    let y = wrapper_s1.result_rx.recv().unwrap();

    println!("{}", y);

    wrapper_s1.handle.join().unwrap();

    // make "CALL" function which gets enum

    //let result1 = wrapper_s1.call(&Subsystem1::add_block, hash);
    //let result2 = wrapper_s2.call(&Subsystem1::submit_transaction, 0x555666666);

    // what happens inside wrapper when one does wrapper_s1.call(...)
    // s2.submit_transaction(&Transaction, 55566666);
    // let func = Subsystem1::add_block; // this is the first param
    // let result = func(&s1, &hash); // this result is returned through the channel
}
