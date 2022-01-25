use std::array;

/******************* IDEA

Core <--> Trait <--> Tunnel <--> Some other core

fn get_tip() -> Id<Block>;
fn get_block(id: &Id<Block>) -> Block;

template <typename Func, typename ReturnType, typename Params...>
ReturnType Call(Func&& func, Params... params)
{
    return func(params...);
}


[External]
fn get_tip() -> Id<Block>;

*/

/******************* The Technique

Lets assume you have an ordered list of N sets of types (“specialization levels”), e.g. (0) Subsystem1, (1) T: Subsystem2, (2) T: Subsystem3.
You want calls of your method foo to dispatch via the first (in the order of your list) set of types that contains the receiver type of the method call,
e.g. String dispatches via (0), while u32 dispatches via (1).

To make this happen, you have to:

- Create the type struct Wrap<T>(T).
- For each specialization level with index i in your list:
- Create a trait Via⟨desc⟩ where ⟨desc⟩ is a good description of that level (e.g. ViaSubsystem2). Add the method foo to this trait.
- Implement that trait for ⟨refs⟩ Wrap<⟨set⟩> where ⟨refs⟩ is simply N - i - 1 times &,
  and ⟨set⟩ describes the set of types for this specialization level. E.g. impl ViaSubsystem1 for &&Wrap<Subsystem1> or impl<T: Subsystem2> ViaSubsystem2 for &Wrap<T>.

For your method call:
- Make sure all Via* traits are in scope.
- Wrap your receiver type ( ⟨refs⟩ Wrap<⟨receiver⟩> ).method() where ⟨refs⟩ is N times & and ⟨receiver⟩ is the original receiver. E.g. (&&&Wrap(r)).method().

https://lukaskalbertodt.github.io/2019/12/05/generalized-autoref-based-specialization.html
https://stackoverflow.com/questions/28519997/what-are-rusts-exact-auto-dereferencing-rules

*/

/*******************  Tagging (complementary technique)

Tagged dispatch strategy with a pair of method calls,
the first using autoderef-based specialization with a reference argument to select a tag,
and the second based on that tag which takes ownership of the original argument.

https://github.com/dtolnay/case-studies/tree/master/autoref-specialization#realistic-application

*/

use std::fmt::{Debug, Display};

struct Wrap<T>(T);

// Subsystem traits
trait Subsystem1 {}
trait Subsystem2 {}
trait Subsystem3 {}

// Specialization trick
trait ViaSubsystem1 {
    fn foo(&self);
}

impl ViaSubsystem1 for &&Wrap<String> {
    fn foo(&self) {
        println!("Via Subsystem1");
    }
}

trait ViaSubsystem2 {
    fn foo(&self);
}

impl<T: Display> ViaSubsystem2 for &Wrap<T> {
    fn foo(&self) {
        println!("Via Subsystem2");
    }
}

trait ViaSubsystem3 {
    fn foo(&self);
}

impl<T: Debug> ViaSubsystem3 for Wrap<T> {
    fn foo(&self) {
        println!("Via Subsystem3");
    }
}

fn main() {
    // Test method calls
    (&&&Wrap(String::from("hi"))).foo();
    (&&&Wrap(3)).foo();
    (&&&Wrap(['a', 'b'])).foo();

    // TODO
    // Replace STRING, DISPLAY and DEBUG with Subsystems

    //(&&&Wrap(Subsystem1)).foo();
    //(&&&Wrap(Subsystem2)).foo();
    //(&&&Wrap(Subsystem3)).foo();
}

// ------------- Multi-Level Currying with (impl Fn) ---------

/*
fn add(x: i32) -> impl Fn(i32) -> Box<dyn Fn(i32) -> i32> {
    move |y: i32| Box::new(move |z: i32| x + y + z)
}

fn main(){
    let add5 = add(5);
        let add5_10 = add5(10);
        println!("Result: {}", add5_10(6)); // prints "Result: 21"
}
*/


// ----------------- type_alias_impl_trait --------------------
/*
#![feature(type_alias_impl_trait)]

type Add1 = impl Fn(u32) -> u32;
type Add2 = impl Fn(u32) -> Add1;

fn add3 (x: u32)
  -> Add2
{
    move |y: u32| {
        move |z: u32| {
            x + y + z
        }
    }
}

fn main ()
{
    assert_eq!(6, add3 (1) (2) (3));
}

*/
