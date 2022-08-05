// Copyright (c) 2021 RBB S.r.l
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

//! Chain script interpreter

use crate::{
    context::{Context, ParseResult},
    error::Error,
    opcodes,
    script::{self, Instruction, Script},
    util,
};
use std::{borrow::Cow, cmp, ops, ops::Range};
use utils::ensure;

/// Item on the data stack.
///
/// The [Cow] type is used to avoid copying data when not necessary. That is often the case with
/// large constants such as public keys and hashes.
type Item<'a> = Cow<'a, [u8]>;

/// Interpreter data stack.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stack<'a>(Vec<Item<'a>>);

impl<'a> Stack<'a> {
    /// Get stack length.
    fn len(&self) -> usize {
        self.0.len()
    }

    /// Check the stack has at least given number of elements and return the length.
    fn at_least(&self, num: usize) -> crate::Result<usize> {
        Some(self.len()).filter(|&l| l >= num).ok_or(Error::NotEnoughElementsOnStack)
    }

    /// Check the stack state represents a successful script verification.
    pub fn verify(&self) -> crate::Result<()> {
        match &self.0[..] {
            [x] => script::read_scriptbool(x).then(|| ()).ok_or(Error::VerifyFail),
            _ => Err(Error::StackNotClean),
        }
    }

    /// Pop an item off of the stack.
    fn pop(&mut self) -> crate::Result<Item<'a>> {
        self.0.pop().ok_or(Error::NotEnoughElementsOnStack)
    }

    /// Pop an item of the top of the stack and convert it to bool.
    fn pop_bool(&mut self) -> crate::Result<bool> {
        Ok(script::read_scriptbool(&self.pop()?))
    }

    /// Pop an item off the stack and convert it to int.
    fn pop_int(&mut self) -> crate::Result<i64> {
        script::read_scriptint(&self.pop()?)
    }

    /// Push an item onto the stack.
    fn push(&mut self, item: Item<'a>) {
        self.0.push(item)
    }

    /// Push a boolean item onto the stack.
    fn push_bool(&mut self, b: bool) {
        self.push_int(b as i64);
    }

    /// Push an integer item onto the stack.
    fn push_int(&mut self, x: i64) {
        self.push(script::build_scriptint(x).into());
    }

    /// Get an element at given position from the top of the stack.
    pub fn top(&self, idx: usize) -> crate::Result<&Item<'a>> {
        self.at_least(idx + 1).map(|len| &self.0[len - idx - 1])
    }

    /// Map range counting from the top of the stack to the internal vector indexing.
    fn top_range(&self, r: Range<usize>) -> crate::Result<Range<usize>> {
        self.at_least(r.end).map(|len| (len - r.end)..(len - r.start))
    }

    /// Take a slice of the top of the stack.
    fn top_slice(&self, r: Range<usize>) -> crate::Result<&[Item<'a>]> {
        Ok(&self.0[self.top_range(r)?])
    }

    /// Take a mutable slice of the top of the stack.
    fn top_slice_mut(&mut self, r: Range<usize>) -> crate::Result<&mut [Item<'a>]> {
        let i = self.top_range(r)?;
        Ok(&mut self.0[i])
    }

    /// Drop given number of elements
    fn drop(&mut self, num_drop: usize) -> crate::Result<()> {
        let len = self.at_least(num_drop)?;
        self.0.truncate(len - num_drop);
        Ok(())
    }

    /// Duplicate slice indexed from the top of the stack. The new items are added to the top of
    /// the stack.
    fn dup(&mut self, r: Range<usize>) -> crate::Result<()> {
        self.top_range(r).map(|i| self.0.extend_from_within(i))
    }

    /// Swap the top `n` elements with the next `n` elements on the stack.
    fn swap(&mut self, n: usize) -> crate::Result<()> {
        let (top, next) = self.top_slice_mut(0..(2 * n))?.split_at_mut(n);
        top.swap_with_slice(next);
        Ok(())
    }

    /// Remove `n`-th element, counting from the top of the stack.
    fn remove(&mut self, n: usize) -> crate::Result<Item<'a>> {
        let len = self.at_least(n + 1)?;
        Ok(self.0.remove(len - n - 1))
    }
}

/// Execution stack keeps track of masks of IF/ELSE branches being executed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExecStack {
    stack: Vec<bool>,
    num_idle: usize,
}

impl ExecStack {
    /// Push mask onto the stack. Executing: true, not executing: false.
    fn push(&mut self, executing: bool) {
        self.stack.push(executing);
        self.num_idle += (!executing) as usize;
    }

    /// Pop the top item off the stack.
    fn pop(&mut self) -> Option<bool> {
        let executing = self.stack.pop()?;
        self.num_idle -= (!executing) as usize;
        Some(executing)
    }

    /// Check if we are currently executing, i.e. no branch is masked out.
    fn executing(&self) -> bool {
        self.num_idle == 0
    }

    /// Check the execution stack is empty, i.e. we are not inside of a conditional.
    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

impl<'a> From<Vec<Item<'a>>> for Stack<'a> {
    fn from(items: Vec<Item<'a>>) -> Self {
        Self(items)
    }
}

/// Verify given witness script against given lock script.
pub fn verify_witness_lock<Ctx: Context>(
    ctx: &Ctx,
    witness: &Script,
    lock: &Script,
) -> crate::Result<()> {
    let stack = run_pushdata(ctx, witness)?;
    let stack = run_script(ctx, lock, stack)?;
    stack.verify()
}

/// Run given script limited to data push operations only.
pub fn run_pushdata<'a, Ctx: Context>(ctx: &Ctx, script: &'a Script) -> crate::Result<Stack<'a>> {
    if script.len() > Ctx::MAX_SCRIPT_SIZE {
        return Err(Error::ScriptSize);
    }
    let mut stack = Stack::default();

    for instr in script.instructions_iter(ctx.enforce_minimal_push()) {
        let instr = instr?;
        match instr {
            Instruction::PushBytes(data) => {
                ensure!(data.len() <= Ctx::MAX_SCRIPT_ELEMENT_SIZE, Error::PushSize);
                stack.push(data.into());
            }
            Instruction::Op(opcode) => {
                if let opcodes::Class::PushNum(x) = opcode.classify() {
                    stack.push_int(x as i64)
                } else {
                    return Err(Error::PushOnly);
                }
            }
        }
        ensure!(stack.len() <= Ctx::MAX_STACK_ELEMENTS, Error::StackSize);
    }

    Ok(stack)
}

/// Run given script with given initial stack.
///
/// Consumes the stack. Returns either an error or the final stack.
pub fn run_script<'a, Ctx: Context>(
    ctx: &Ctx,
    script: &'a Script,
    mut stack: Stack<'a>,
) -> crate::Result<Stack<'a>> {
    if script.len() > Ctx::MAX_SCRIPT_SIZE {
        return Err(Error::ScriptSize);
    }

    let mut instr_iter = script.instructions_iter(ctx.enforce_minimal_push());
    let mut subscript: &[u8] = instr_iter.subscript();
    let mut cur_instr_num = 0u32;
    let mut codesep_idx = u32::MAX;
    let mut exec_stack = ExecStack::default();
    let mut alt_stack = Stack::<'a>::default();

    while let Some(instr) = instr_iter.next() {
        let instr = instr?;

        let executing = exec_stack.executing();
        match instr {
            Instruction::PushBytes(data) => {
                ensure!(data.len() <= Ctx::MAX_SCRIPT_ELEMENT_SIZE, Error::PushSize);
                if executing {
                    stack.push(data.into());
                }
            }
            Instruction::Op(opcode) => match opcode.classify() {
                opcodes::Class::NoOp => (),
                opcodes::Class::IllegalOp => return Err(Error::IllegalOp),
                opcodes::Class::ReturnOp if executing => return Err(Error::VerifyFail),
                opcodes::Class::PushNum(x) if executing => stack.push_int(x as i64),
                opcodes::Class::PushBytes(_) => {
                    unreachable!("Already handled using Instruction::PushBytes")
                }
                opcodes::Class::PushData(_) => {
                    unreachable!("Already handled using Instruction::PushBytes")
                }
                opcodes::Class::AltStack(opc) if executing => match opc {
                    opcodes::AltStack::OP_TOALTSTACK => alt_stack.push(stack.pop()?),
                    opcodes::AltStack::OP_FROMALTSTACK => stack.push(alt_stack.pop()?),
                },
                opcodes::Class::Signature(sig_opcode) if executing => {
                    match sig_opcode {
                        opcodes::Signature::OP_CHECKSIG | opcodes::Signature::OP_CHECKSIGVERIFY => {
                            let pubkey = stack.pop()?;
                            let sig = stack.pop()?;
                            // Treat plain CHECKSIG as 1-of-1 MULTISIG
                            let result = check_multisig(
                                ctx,
                                core::iter::once(sig.as_ref()),
                                core::iter::once(pubkey.as_ref()),
                                subscript,
                                codesep_idx,
                            )?;
                            stack.push_bool(result);
                        }
                        opcodes::Signature::OP_CHECKMULTISIG
                        | opcodes::Signature::OP_CHECKMULTISIGVERIFY => {
                            // Extract keys
                            let nkey = stack.pop_int()?;
                            ensure!(nkey >= 0, Error::PubkeyCount);
                            let nkey = nkey as usize;
                            ensure!(nkey <= Ctx::MAX_PUBKEYS_PER_MULTISIG, Error::PubkeyCount);
                            let keys = stack.top_slice(0..nkey)?.iter().map(AsRef::as_ref);

                            // Extract signatures
                            let nsig = script::read_scriptint(stack.top(nkey)?)?;
                            ensure!(nsig >= 0, Error::SigCount);
                            let nsig = nsig as usize;
                            ensure!(nsig <= nkey, Error::SigCount);
                            let sig_range = (nkey + 1)..(nsig + nkey + 1);
                            let sigs = stack.top_slice(sig_range)?.iter().map(AsRef::as_ref);

                            // Verify
                            let result = check_multisig(ctx, sigs, keys, subscript, codesep_idx)?;

                            // Clean up stack, ensure! dummy 0.
                            stack.drop(nsig + nkey + 1)?;
                            ensure!(stack.pop()?.is_empty(), Error::NullDummy);
                            stack.push_bool(result);
                        }
                    }
                    ensure!(
                        !sig_opcode.is_verify() || stack.pop_bool()?,
                        Error::VerifyFail
                    );
                }
                opcodes::Class::ControlFlow(cf) => match cf {
                    opcodes::ControlFlow::OP_CODESEPARATOR => {
                        subscript = instr_iter.subscript();
                        codesep_idx = cur_instr_num;
                    }
                    opcodes::ControlFlow::OP_IF | opcodes::ControlFlow::OP_NOTIF => {
                        let cond = executing && {
                            let cond = match stack.pop()?.as_ref() {
                                c if !ctx.enforce_minimal_if() => script::read_scriptbool(c),
                                &[] => false,
                                &[1u8] => true,
                                _ => return Err(Error::InvalidOperand),
                            };
                            cond ^ (cf == opcodes::ControlFlow::OP_NOTIF)
                        };
                        exec_stack.push(cond);
                    }
                    opcodes::ControlFlow::OP_ELSE => {
                        let top_executing = exec_stack.pop().ok_or(Error::UnbalancedIfElse)?;
                        exec_stack.push(!top_executing);
                    }
                    opcodes::ControlFlow::OP_ENDIF => {
                        let _ = exec_stack.pop().ok_or(Error::UnbalancedIfElse)?;
                    }
                },
                opcodes::Class::TimeLock(opcode) if executing => {
                    let time = script::read_scriptint_size(stack.top(0)?.as_ref(), 5)?;
                    let ok = match opcode {
                        opcodes::TimeLock::OP_CLTV => ctx.check_lock_time(time),
                        opcodes::TimeLock::OP_CSV => ctx.check_sequence(time),
                    };
                    ensure!(ok, Error::TimeLock);
                }
                opcodes::Class::Ordinary(opcode) if executing => {
                    execute_opcode(opcode, &mut stack)?;
                }
                _ => (),
            },
        }

        ensure!(
            (stack.len() + alt_stack.len()) <= Ctx::MAX_STACK_ELEMENTS,
            Error::StackSize
        );
        cur_instr_num = cur_instr_num.saturating_add(1);
    }

    // Check OP_IF/OP_NOTIF has been closed properly wiht OP_ENDIF.
    if !exec_stack.is_empty() {
        return Err(Error::UnbalancedIfElse);
    }

    Ok(stack)
}

/// Check whether given signatures are valid for given pubkeys.
/// Some pubkeys may not have signatures to go with them.
fn check_multisig<'a, Ctx: Context>(
    ctx: &Ctx,
    mut sigs: impl Iterator<Item = &'a [u8]> + ExactSizeIterator,
    mut pubkeys: impl Iterator<Item = &'a [u8]> + ExactSizeIterator,
    subscript: &[u8],
    codesep_idx: u32,
) -> crate::Result<bool> {
    // Check each signature has its corresponding pubkey.
    while let Some(sig) = sigs.next() {
        loop {
            if pubkeys.len() < sigs.len() + 1 {
                // Not enough pubkeys to cover all the remaining signatures.
                // We add 1 to the number of signatures left in the condition to account for the
                // signature being processed that has just been taken out of the iterator.
                return Ok(false);
            }
            match ctx.parse_pubkey(pubkeys.next().expect("pubkeys run out")) {
                // error -> quit immediately
                ParseResult::Err => return Err(Error::PubkeyFormat),
                // unrecognized pubkey type -> accept and continue
                ParseResult::Reserved => break,
                // parsed a pubkey -> check signature
                ParseResult::Ok(pubkey) => {
                    if let Some(sigdata) = ctx.parse_signature(pubkey, sig) {
                        if ctx.verify_signature(&sigdata, subscript, codesep_idx) {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(true)
}

/// Execute an ["ordinay"](opcodes::Ordinary) opcode.
fn execute_opcode(opcode: opcodes::Ordinary, stack: &mut Stack<'_>) -> crate::Result<()> {
    use opcodes::Ordinary as Opc;

    match opcode {
        // Verify. Do nothing now, the actual verification is handled below this match statement.
        Opc::OP_VERIFY => (),

        // Main stack manipulation
        Opc::OP_DROP => stack.drop(1)?,
        Opc::OP_2DROP => stack.drop(2)?,
        Opc::OP_DUP => stack.dup(0..1)?,
        Opc::OP_2DUP => stack.dup(0..2)?,
        Opc::OP_3DUP => stack.dup(0..3)?,
        Opc::OP_OVER => stack.dup(1..2)?,
        Opc::OP_2OVER => stack.dup(2..4)?,
        Opc::OP_SWAP => stack.swap(1)?,
        Opc::OP_2SWAP => stack.swap(2)?,
        Opc::OP_2ROT => {
            let top = stack.top_slice_mut(0..6)?;
            let nth = |n: usize| top[n].clone();
            let to_put = [nth(2), nth(3), nth(4), nth(5), nth(0), nth(1)];
            top.clone_from_slice(&to_put);
        }
        Opc::OP_NIP => {
            let x = stack.pop()?;
            let _ = stack.pop()?;
            stack.push(x);
        }
        Opc::OP_PICK => {
            let i = stack.pop_int()?;
            ensure!(i >= 0, Error::InvalidOperand);
            stack.push(stack.top(i as usize)?.clone());
        }
        Opc::OP_ROLL => {
            let i = stack.pop_int()?;
            ensure!(i >= 0, Error::InvalidOperand);
            let x = stack.remove(i as usize)?;
            stack.push(x);
        }
        Opc::OP_ROT => {
            let x = stack.remove(2)?;
            stack.push(x);
        }
        Opc::OP_TUCK => {
            let x = stack.top(0)?.clone();
            stack.swap(1)?;
            stack.push(x);
        }
        Opc::OP_IFDUP => {
            let item = stack.top(0)?;
            if script::read_scriptbool(item) {
                let item_clone = item.clone();
                stack.push(item_clone);
            }
        }
        Opc::OP_DEPTH => {
            ensure!(stack.len() < i32::MAX as usize, Error::NumericOverflow);
            stack.push_int(stack.len() as i64);
        }

        // Stack item queries
        Opc::OP_SIZE => {
            let top_len = stack.top(0)?.len();
            ensure!(top_len < i32::MAX as usize, Error::NumericOverflow);
            stack.push_int(top_len as i64);
        }
        Opc::OP_EQUAL | Opc::OP_EQUALVERIFY => {
            let y = stack.pop()?;
            let x = stack.pop()?;
            stack.push_bool(x == y);
        }

        // Arithmetic
        Opc::OP_1ADD => op_num1(stack, |x| x + 1)?,
        Opc::OP_1SUB => op_num1(stack, |x| x - 1)?,
        Opc::OP_NEGATE => op_num1(stack, ops::Neg::neg)?,
        Opc::OP_ABS => op_num1(stack, i64::abs)?,
        Opc::OP_NOT => op_num1(stack, |x| (x == 0) as i64)?,
        Opc::OP_0NOTEQUAL => op_num1(stack, |x| (x != 0) as i64)?,
        Opc::OP_ADD => op_num2(stack, ops::Add::add)?,
        Opc::OP_SUB => op_num2(stack, ops::Sub::sub)?,
        Opc::OP_BOOLAND => op_num2(stack, |x, y| (x != 0 && y != 0) as i64)?,
        Opc::OP_BOOLOR => op_num2(stack, |x, y| (x != 0 || y != 0) as i64)?,
        Opc::OP_NUMEQUAL | Opc::OP_NUMEQUALVERIFY => op_num2(stack, |x, y| (x == y) as i64)?,
        Opc::OP_NUMNOTEQUAL => op_num2(stack, |x, y| (x != y) as i64)?,
        Opc::OP_LESSTHAN => op_num2(stack, |x, y| (x < y) as i64)?,
        Opc::OP_GREATERTHAN => op_num2(stack, |x, y| (x > y) as i64)?,
        Opc::OP_LESSTHANOREQUAL => op_num2(stack, |x, y| (x <= y) as i64)?,
        Opc::OP_GREATERTHANOREQUAL => op_num2(stack, |x, y| (x >= y) as i64)?,
        Opc::OP_MIN => op_num2(stack, cmp::min)?,
        Opc::OP_MAX => op_num2(stack, cmp::max)?,
        Opc::OP_WITHIN => {
            let hi = stack.pop_int()?;
            let lo = stack.pop_int()?;
            let x = stack.pop_int()?;
            stack.push_int((lo..hi).contains(&x) as i64);
        }

        // Hashes
        Opc::OP_RIPEMD160 => op_hash(stack, util::ripemd160)?,
        Opc::OP_SHA1 => op_hash(stack, util::sha1)?,
        Opc::OP_SHA256 => op_hash(stack, util::sha256)?,
        Opc::OP_HASH160 => op_hash(stack, util::hash160)?,
        Opc::OP_HASH256 => op_hash(stack, util::hash256)?,
    }

    ensure!(!opcode.is_verify() || stack.pop_bool()?, Error::VerifyFail);
    Ok(())
}

/// Perform an unary arithmetic operation on the top of the stack.
fn op_num1(stack: &mut Stack, f: impl FnOnce(i64) -> i64) -> crate::Result<()> {
    let x = stack.pop_int()?;
    stack.push_int(f(x));
    Ok(())
}

/// Perform a binary arithmetic operation on the top of the stack.
fn op_num2(stack: &mut Stack, f: impl FnOnce(i64, i64) -> i64) -> crate::Result<()> {
    let y = stack.pop_int()?;
    let x = stack.pop_int()?;
    stack.push_int(f(x, y));
    Ok(())
}

/// Perform a byte-array based function on the top stack item. Useful for hashes.
fn op_hash<T: AsRef<[u8]>>(stack: &mut Stack, f: impl FnOnce(&[u8]) -> T) -> crate::Result<()> {
    let result = f(&stack.pop()?);
    stack.push(Cow::Owned(result.as_ref().to_vec()));
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::opcodes::all as opc;
    use crate::{context::testcontext::TestContext, script::Builder, util::sha256};
    use hex_literal::hex;
    use proptest::{collection::SizeRange, prelude::*};

    #[test]
    fn unit_exec_stack() {
        let mut exec_stack = ExecStack::default();
        assert!(exec_stack.executing());

        exec_stack.push(true);
        assert!(exec_stack.executing());
        exec_stack.push(false);
        assert!(!exec_stack.executing());
        exec_stack.push(true);
        assert!(!exec_stack.executing());

        // [true, false, true]
        let _ = exec_stack.pop();
        // [true, false]
        assert!(!exec_stack.executing());
        let _ = exec_stack.pop();
        // [true]
        assert!(exec_stack.executing());
        let _ = exec_stack.pop();
        // []
        assert!(exec_stack.executing());

        assert!(exec_stack.stack.is_empty());
    }

    fn testcase_op_verify(update_stack: impl FnOnce(&mut Stack), expected: crate::Result<Stack>) {
        let script = Builder::new().push_opcode(opcodes::all::OP_VERIFY).into_script();
        let mut stack = Stack::default();
        update_stack(&mut stack);
        let result = run_script(&TestContext::default(), &script, stack);
        assert_eq!(result, expected);
    }

    #[test]
    fn unit_op_verify_true() {
        testcase_op_verify(|s| s.push_bool(true), Ok(Stack::default()));
    }

    #[test]
    fn unit_op_verify_false() {
        testcase_op_verify(|s| s.push_bool(false), Err(Error::VerifyFail));
    }

    #[test]
    fn unit_op_verify_empty() {
        testcase_op_verify(|_| (), Err(Error::NotEnoughElementsOnStack));
    }

    #[test]
    fn unit_if_then_else_syntax() {
        use opcodes::all::{OP_ELSE, OP_ENDIF, OP_IF, OP_NOTIF};
        let should_fail = |script: Script| {
            let stack = Stack(vec![vec![].into(), vec![].into()]);
            let result = run_script(&TestContext::default(), &script, stack);
            assert_eq!(result, Err(Error::UnbalancedIfElse));
        };
        should_fail(Builder::new().push_opcode(OP_IF).into_script());
        should_fail(Builder::new().push_opcode(OP_IF).push_opcode(OP_ELSE).into_script());
        should_fail(Builder::new().push_opcode(OP_IF).push_opcode(OP_NOTIF).into_script());
        should_fail(Builder::new().push_opcode(OP_ELSE).into_script());
        should_fail(Builder::new().push_opcode(OP_ENDIF).into_script());
        should_fail(
            Builder::new()
                .push_opcode(OP_IF)
                .push_opcode(OP_IF)
                .push_opcode(OP_ELSE)
                .push_opcode(OP_ENDIF)
                .into_script(),
        );
        should_fail(
            Builder::new()
                .push_opcode(OP_IF)
                .push_opcode(OP_ELSE)
                .push_opcode(OP_ENDIF)
                .push_opcode(OP_ENDIF)
                .into_script(),
        );
    }

    #[test]
    fn unit_checksig_not_executed() {
        use opcodes::all::*;
        let script = Builder::new()
            .push_int(0)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_ENDIF)
            .into_script();
        let result = run_script(&TestContext::default(), &script, vec![].into());
        assert_eq!(result, Ok(vec![].into()));
    }

    #[test]
    fn unit_multisig() {
        let ctx = TestContext::default();
        let txhash = sha256(&ctx.transaction);
        let sign_by = |pk: [u8; 4]| -> [u8; 4] {
            [pk[0] ^ txhash[0], pk[1] ^ txhash[1], pk[2] ^ txhash[2], pk[3] ^ txhash[3]]
        };

        let keys = [hex!("01010101"), hex!("02020202"), hex!("03030303"), hex!("04040404")];
        let sig0 = sign_by(hex!("00000000"));
        let sig1 = sign_by(hex!("01010101"));
        let sig2 = sign_by(hex!("02020202"));
        let sig3 = sign_by(hex!("03030303"));
        let sig4 = sign_by(hex!("04040404"));

        let test_case = |sigs: &[[u8; 4]], expected: crate::Result<bool>| {
            let result = check_multisig(
                &ctx,
                sigs.iter().map(AsRef::as_ref),
                keys.iter().map(AsRef::as_ref),
                &[],
                0,
            );
            assert_eq!(result, expected);
        };

        // sig0 is not in the set of public keys, this should fail
        test_case(&[sig1, sig0][..], Ok(false));
        // This should be fine, sig1 and sig2 in the correct order
        test_case(&[sig1, sig2][..], Ok(true));
        // Try first and last
        test_case(&[sig1, sig4][..], Ok(true));
        // And last two
        test_case(&[sig3, sig4][..], Ok(true));
        // This should fail due to incorrect signature order
        test_case(&[sig2, sig1][..], Ok(false));
        // Now with all the signatures.
        test_case(&[sig1, sig2, sig3, sig4][..], Ok(true));
        // Duplicate signature should not count as two sigs.
        test_case(&[sig1, sig1][..], Ok(false));
        // Last one should fail.
        test_case(&[sig1, sig2, sig3, sig0][..], Ok(false));
    }

    #[test]
    fn unit_conditional_altstack() {
        use opcodes::all::*;
        let script = Builder::new()
            .push_int(1337)
            .push_int(0)
            .push_opcode(OP_IF)
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_ENDIF)
            .into_script();
        let result = run_script(&TestContext::default(), &script, vec![].into());
        let expected = vec![script::build_scriptint(1337).into()].into();
        assert_eq!(result, Ok(expected));
    }

    use prop::collection::vec as gen_vec;

    // Generate stack item as an array of bytes
    fn gen_item_bytes<'a>(num_bytes: Range<usize>) -> impl Strategy<Value = Item<'a>> {
        gen_vec(prop::num::u8::ANY, num_bytes).prop_map(|v| v.into())
    }

    // Generate stack with given item generation strategy.
    fn gen_stack<'a>(
        gen_item: impl Strategy<Value = Item<'a>>,
        size: impl Into<SizeRange>,
    ) -> impl Strategy<Value = Stack<'a>> {
        gen_vec(gen_item, size).prop_map(Stack)
    }

    proptest! {
        // Interpreter should not panic regardless of its inputs, even garbage.
        #[test]
        fn prop_dont_panic(stack in gen_stack(gen_item_bytes(0..40), 0..40),
                           script: Vec<u8>) {
            let script: Script = script.into();
            let _ = run_script(&TestContext::default(), &script, stack);
        }

        #[test]
        fn prop_exec_stack_push(items in gen_vec(prop::bool::ANY, 0..9)) {
            let mut exec_stack = ExecStack::default();
            items.iter().for_each(|i| exec_stack.push(*i));

            // Check the final state of the execution stack
            assert_eq!(items, exec_stack.stack);
            // Check number of idle lanes is correct
            assert_eq!(items.iter().filter(|i| !**i).count(), exec_stack.num_idle);
            // Check whether executing indicator is correct
            assert_eq!(items.iter().all(|i| *i), exec_stack.executing());
        }

        #[test]
        fn prop_exec_stack_push_pop(items0 in gen_vec(prop::bool::ANY, 0..9),
                                    items1 in gen_vec(prop::bool::ANY, 1..9)) {
            let mut exec_stack = ExecStack::default();
            items0.iter().for_each(|i| exec_stack.push(*i));
            let orig_exec_stack = exec_stack.clone();

            // Push a bunch of extra items and pop them again
            items1.iter().for_each(|i| exec_stack.push(*i));
            items1.iter().for_each(|_| exec_stack.pop().map(|_| ()).unwrap());

            // Check we got to the original state
            assert_eq!(orig_exec_stack, exec_stack);
        }

        #[test]
        fn prop_2dup(mut stack in gen_stack(gen_item_bytes(0..40), 2..10)) {
            let res = execute_opcode(opcodes::Ordinary::OP_2DUP, &mut stack);
            prop_assert!(res.is_ok());
            prop_assert_eq!(stack.top(0), stack.top(2));
            prop_assert_eq!(stack.top(1), stack.top(3));
        }

        #[test]
        fn prop_swap_swap(orig_stack in gen_stack(gen_item_bytes(0..40), 2..5)) {
            let mut stack = orig_stack.clone();
            execute_opcode(opcodes::Ordinary::OP_SWAP, &mut stack).unwrap();
            execute_opcode(opcodes::Ordinary::OP_SWAP, &mut stack).unwrap();
            prop_assert_eq!(orig_stack.0, stack.0);
        }

        #[test]
        fn prop_if_then(cond: bool, then_val: i32, else_val: i32) {
            let script = Builder::new()
                .push_int(cond as i64)
                .push_opcode(opcodes::all::OP_IF)
                .push_int(then_val as i64)
                .push_opcode(opcodes::all::OP_ELSE)
                .push_int(else_val as i64)
                .push_opcode(opcodes::all::OP_ENDIF)
                .into_script();

            let stack = Stack::default();
            let ctx = TestContext::default();
            let result = run_script(&ctx, &script, stack);
            prop_assert!(result.is_ok());

            let expected = cond.then(|| then_val).unwrap_or(else_val) as i64;
            let expected_stack = Stack(vec![script::build_scriptint(expected).into()]);
            prop_assert_eq!(result.unwrap(), expected_stack);
        }

        #[test]
        fn prop_2rot(orig_stack in gen_stack(gen_item_bytes(0..40), 6..10)) {
            let mut stack = orig_stack.clone();
            execute_opcode(opcodes::Ordinary::OP_2ROT, &mut stack).unwrap();
            prop_assert_eq!(stack.len(), orig_stack.len());
            prop_assert_eq!(stack.top(0), orig_stack.top(4));
            prop_assert_eq!(stack.top(1), orig_stack.top(5));
            prop_assert_eq!(stack.top(2), orig_stack.top(0));
            prop_assert_eq!(stack.top(3), orig_stack.top(1));
            prop_assert_eq!(stack.top(4), orig_stack.top(2));
            prop_assert_eq!(stack.top(5), orig_stack.top(3));
            prop_assert_eq!(stack.top_slice(6..stack.len()), orig_stack.top_slice(6..stack.len()));
        }

        #[test]
        fn prop_shuffle(
            mut orig_stack in gen_stack(gen_item_bytes(0..40), 6..10),
            opcode in prop::sample::select(&[
                opcodes::Ordinary::OP_ROT,
                opcodes::Ordinary::OP_SWAP,
                opcodes::Ordinary::OP_2ROT,
                opcodes::Ordinary::OP_2SWAP,
            ][..]),
        ) {
            let mut stack = orig_stack.clone();
            execute_opcode(opcode, &mut stack).unwrap();

            // These opcodes only rearrange items on the stack, they should not duplicate, drop or
            // create new items. I.e. the before and after stack should be identical after putting
            // each in the canonical order.
            stack.0.sort();
            orig_stack.0.sort();
            prop_assert_eq!(stack, orig_stack);
        }

        #[test]
        fn prop_stack_manipulation(
            orig_stack in gen_stack(gen_item_bytes(0..40), 6..10),
            opcode in prop::sample::select(&[
                opcodes::Ordinary::OP_DROP,
                opcodes::Ordinary::OP_2DROP,
                opcodes::Ordinary::OP_DUP,
                opcodes::Ordinary::OP_2DUP,
                opcodes::Ordinary::OP_3DUP,
                opcodes::Ordinary::OP_OVER,
                opcodes::Ordinary::OP_2OVER,
                opcodes::Ordinary::OP_SWAP,
                opcodes::Ordinary::OP_2SWAP,
                opcodes::Ordinary::OP_2ROT,
                opcodes::Ordinary::OP_NIP,
                opcodes::Ordinary::OP_ROT,
                opcodes::Ordinary::OP_TUCK,
                opcodes::Ordinary::OP_IFDUP,
            ][..]),
        ) {
            let mut stack = orig_stack.clone();
            execute_opcode(opcode, &mut stack).unwrap();
            // These opcodes should not fabricate elements out of thin air.
            prop_assert!(stack.0.iter().all(|item| orig_stack.0.iter().any(|i| i == item)));
        }

        #[test]
        fn prop_pushdata_eq(data in gen_vec(gen_vec(prop::num::u8::ANY, 0..500), 0..20)) {
            let mut builder = Builder::default();
            for x in &data {
                builder = builder.push_slice_minimal(x);
            }
            let script = builder.into_script();
            let stack0 = run_pushdata(&TestContext::default(), &script);
            let stack1 = run_script(&TestContext::default(), &script, Stack::default());
            prop_assert!(stack0.is_ok());
            prop_assert_eq!(&stack0, &stack1);
            prop_assert_eq!(stack0.unwrap().0, data);
        }

        #[test]
        fn prop_stack_limit(use_alt in gen_vec(prop::bool::ANY, 499)) {
            let mut builder = Builder::new().push_int(0).push_int(0).push_int(0);
            for alt in use_alt {
                builder = builder.push_opcode(opcodes::all::OP_2DUP);
                if alt {
                    builder = builder.push_opcode(opcodes::all::OP_TOALTSTACK);
                }
            }
            let script = builder.into_script();
            let result = run_script(&TestContext::default(), &script, vec![].into());
            prop_assert_eq!(result, Err(Error::StackSize));
        }

        #[test]
        fn prop_abs_time_lock(cur_block in 0i64..100_000, lock_time in 0i64..100_000) {
            let script = Builder::new().push_int(lock_time).push_opcode(opc::OP_CLTV).into_script();
            let ctx = TestContext::new_at_height(Vec::new(), cur_block as u64);
            let result = run_script(&ctx, &script, Vec::new().into());
            if cur_block >= lock_time {
                let final_stack = vec![script::build_scriptint(lock_time).into()].into();
                prop_assert_eq!(result, Ok(final_stack));
            } else {
                prop_assert_eq!(result, Err(Error::TimeLock));
            }
        }
    }
}
