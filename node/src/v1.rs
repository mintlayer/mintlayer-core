
use std::collections::HashMap;
//mod future_utils;
use std::thread;
//use std::thread::JoinHandle;
use std::time::Duration;
use tokio::task;
use tokio::task::JoinHandle;

//use future_utils::{new_executor_and_spawner, Executor, Spawner};

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
    fn init(&mut self) -> JoinHandle<()>;
    fn call<F: Fn(U) -> (), U>(&mut self, func: F, arg: U);
}

// Implementation of Subsystem1
impl Subsystem1 {
    pub fn add_block(&mut self, hash: &u128) -> Result<(), Box<dyn std::error::Error>> {
        self.block_counter += 1;
        self.block_hash.push(*hash);
        println!("Hash {} added as block num {}", *hash, self.block_counter);
        Ok(())
    }
}

impl Launch for Subsystem1 {
    fn init(&mut self) -> JoinHandle<()> {
        task::spawn(async {
            self.block_counter = 0;
            self.block_hash = Vec::new();
            println!("Init Subsystem1 Thread");
        })
    }

    fn call<F, U>(&mut self, func: F, arg: U)
    where
        F: Fn(U) -> (),
    {
        func(arg);
    }
}

// Implementation of Subsystem2
impl Subsystem2 {
    pub fn submit_transaction(
        &self,
        tx: &Transaction,
        timestamp: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!();
    }
}

impl Launch for Subsystem2 {
    fn init(&mut self) -> JoinHandle<()> {
        task::spawn(async {
            println!("Init Subsystem2 Thread");
        })
    }

    fn call<F, U>(&mut self, func: F, arg: U) {
        todo!()
    }
}

// Implement Wrapper

struct Wrap;

impl Wrap {
    fn instantiate<T: Launch>() -> JoinHandle<()> {
        T::init()
    }
}
#[tokio::main]
async fn main() {
    // -----------------------Template-------------------------------
    //let s1 = Subsystem1;
    //let s2 = Subsystem2;

    // Future for Subsystem Thread
    //let wrapper_s1 = Wrap::Launch::<Subsystem1>(&Subsystem1::init);
    //let wrapper_s2 = Wrap::Launch::<Subsystem2>(&Subsystem2::init);

    let hash = 0;
    let value = 0x55566666;

    //let result = wrapper_s1.call(&Subsystem1::add_block, hash);
    // Internally does :  s1.add_block(&0);
    // what happens inside wrapper when one does wrapper_s1.call(...)
    /*
    let func = Subsystem1::add_block; // this is the first param
    let result = func(&s1, &hash); // this result is returned through the channel
    */

    //let result = wrapper_s1.call(&Subsystem2::submit_transaction, 55566666);
    // Internally Does s2.submit_transaction(&Transaction, 55566666);

    // ----------------------------RAW--------------------------------

    //let (executor, spawner) = new_executor_and_spawner();

    // Spawn a task to print before and after waiting on a timer.
    /*
    spawner.spawn(async {
        println!("howdy!");
        println!("done!");
    });
    */
    // Drop the spawner so that our executor knows it is finished and won't
    // receive more incoming tasks to run.
    //drop(&spawner);

    // Run the executor until the task queue is empty.
    // This will print "howdy!", then print "done!".
    //executor.run();

    // -----------------------Wrapped-------------------------------

    let wrap_sys1 = Wrap::instantiate::<Subsystem1>();
    let wrap_sys2 = Wrap::instantiate::<Subsystem2>();

    //let result1 = wrap_sys1.call::<Subsystem1>(&Subsystem1::add_block, hash);
    //let result2 = wrap_sys1.call::<Subsystem2>(&Subsystem2::submit_transaction, value);
}
