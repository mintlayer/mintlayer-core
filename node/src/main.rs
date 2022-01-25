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

// struct Subsystem2 {
//     tx_count: u32,
//     mempool: Vec<u128>,
// }

impl Subsystem1 {
    pub fn simple_add(&mut self, x: i32, y: i32) -> i32 {
        x + y
    }

    pub fn add_block(&mut self, hash: &u128) -> u128 {
        self.block_counter += 1;
        self.block_hash.push(hash.clone());
        *hash ^ 0x87654321FEDCBA90
    }

    pub fn init() -> Self {
        let block_counter = 0;
        let block_hash: Vec<u128> = vec![0]; // GENESIS

        Subsystem1 {
            block_counter,
            block_hash,
        }
    }

    pub fn shutdown() {}
}

struct Wrap {
    call: Sender<Subsystem1Callables>,
    handle: JoinHandle<()>,
    result_rx: Receiver<Subsystem1Returnable>,
}

impl Wrap {
    fn launch(func: fn() -> Subsystem1) -> Self {
        type F = (for<'r> fn(&'r mut Subsystem1, i32, i32) -> i32, i32, i32);

        let (tx, rx) = mpsc::channel::<Subsystem1Callables>();
        let (tx2, rx2) = mpsc::channel::<Subsystem1Returnable>();

        let handle = thread::spawn(move || {
            // TODO SOMETHING HERER
            let instance: &mut Subsystem1 = &mut func();
            loop {
                let t = rx.recv().unwrap();
                let result = t.call(instance);
                tx2.send(result).unwrap();
            }
        });

        Wrap {
            call: tx,
            handle: handle,
            result_rx: rx2,
        }
    }
}

/* For polymorphism we used enum instead of traits, both for parameters and return types
https://www.mattkennedy.io/blog/rust_polymorphism/
 */

/* Type encompassing : The variants of enums are not considered types in their own right,
meaning one cannot create functions that only work with an individual variant from the enum.
This can be solved by creating the types using structs and wrapping them in an enum
*/

/*Higher-Rank Trait Bounds (HRTBs)
for<'a> F can be read as "for all choices of 'a",
and basically produces an infinite list of trait bounds that F must satisfy.
*/

enum Subsystem1Callables {
    SimpleAdd {
        func: for<'r> fn(&'r mut Subsystem1, i32, i32) -> i32,
        A: i32,
        B: i32,
    },

    AddBlock {
        func: for<'r> fn(&'r mut Subsystem1, &u128) -> u128,
        H: u128,
    },

    Init,
    Shutdown,
}

#[derive(Debug)]
enum Subsystem1Returnable {
    R1(i32),
    R2(u128),
    R3(i32),
    R4(i32),
}

impl Subsystem1Callables {
    fn call(&self, S: &mut Subsystem1) -> Subsystem1Returnable {
        match self {
            Subsystem1Callables::SimpleAdd { func, A, B } => {
                Subsystem1Returnable::R1(func(S, *A, *B))
            }
            Subsystem1Callables::AddBlock { func, H } => Subsystem1Returnable::R2(func(S, H)),
            Subsystem1Callables::Init {} => Subsystem1Returnable::R3(1),
            Subsystem1Callables::Shutdown {} => Subsystem1Returnable::R4(0),
        }
    }
}

fn main() {
    // create a thread in each Subsystem and return a future
    let wrapper_s1 = Wrap::launch(Subsystem1::init);

    let hash = 0x123456789ABCDEF;

    // Channels
    wrapper_s1
        .call
        .send(Subsystem1Callables::SimpleAdd {
            func: Subsystem1::simple_add,
            A: 3,
            B: 4,
        })
        .unwrap();

    wrapper_s1
        .call
        .send(Subsystem1Callables::AddBlock {
            func: Subsystem1::add_block,
            H: hash,
        })
        .unwrap();

    let y = wrapper_s1.result_rx.recv().unwrap();
    let z = wrapper_s1.result_rx.recv().unwrap();

    println!("ADD = {:?}, BLOCK = {:?} ", y, z);

    wrapper_s1.handle.join().unwrap();

    // what happens inside wrapper when one does wrapper_s1.call(...)
    // s2.submit_transaction(&Transaction, 55566666);
    // let func = Subsystem1::add_block; // this is the first param
    // let result = func(&s1, &hash); // this result is returned through the channel
}
