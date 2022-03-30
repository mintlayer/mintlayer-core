// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(clippy::new_without_default, clippy::result_unit_err)]
use parity_scale_codec::{Decode, Encode};
use rand::Rng;
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};

pub type Hash = u64;
pub type Amount = u64;
pub type BlockId = u64;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    vin: Vec<(Hash, Amount)>,
    vout: Vec<(Hash, Amount)>,
}

impl Transaction {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        let vin: Vec<(Hash, Amount)> = (0..rng.gen_range(1..5))
            .map(|_| {
                let hash: Hash = rng.gen::<u64>();
                let amount: Amount = rng.gen_range(1000..10000);
                (hash, amount)
            })
            .collect::<_>();

        let vout: Vec<(Hash, Amount)> = (0..rng.gen_range(1..3))
            .map(|_| {
                let hash: Hash = rng.gen::<u64>();
                let amount: Amount = rng.gen_range(1..1000);
                (hash, amount)
            })
            .collect::<_>();

        Self { vin, vout }
    }
}

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub id: BlockId,
    pub prev_id: Option<BlockId>,
}

impl BlockHeader {
    pub fn new(prev_id: Option<BlockId>) -> Self {
        let mut rng = rand::thread_rng();

        Self {
            id: rng.gen::<u64>() as BlockId,
            prev_id,
        }
    }

    pub fn with_id(id: BlockId, prev_id: Option<BlockId>) -> Self {
        Self { id, prev_id }
    }

    pub fn genesis() -> Self {
        let mut rng = rand::thread_rng();

        Self {
            id: rng.gen::<u64>() as BlockId,
            prev_id: None,
        }
    }
}

impl crate::sync::queue::Orderable for BlockHeader {
    type Id = BlockId;

    fn get_id(&self) -> &Self::Id {
        &self.id
    }

    fn get_prev_id(&self) -> &Option<Self::Id> {
        &self.prev_id
    }
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(prev_id: Option<BlockId>) -> Self {
        let mut rng = rand::thread_rng();

        let transactions: Vec<Transaction> =
            (0..rng.gen_range(4..8)).map(|_| Transaction::new()).collect::<_>();

        Self {
            header: BlockHeader::new(prev_id),
            transactions,
        }
    }

    pub fn get_id(&self) -> BlockId {
        self.header.id
    }
}

#[derive(Clone)]
pub struct Storage<T> {
    pub store: BTreeMap<BlockId, T>,
}

impl<T> Storage<T> {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, id: BlockId, data: T) {
        self.store.insert(id, data);
    }

    pub fn remove(&mut self, id: &BlockId) -> Option<T> {
        self.store.remove(id)
    }

    pub fn get(&self, id: &BlockId) -> Option<&T> {
        self.store.get(id)
    }

    pub fn get_mut(&mut self, id: &BlockId) -> Option<&mut T> {
        self.store.get_mut(id)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct BlockIndex {
    pub blkid: BlockId,
    pub prev_blkid: Option<BlockId>,
    pub next_blkid: Option<BlockId>,
    pub trust: u64,
    pub height: u64,
}

impl BlockIndex {
    pub fn new(
        blkid: BlockId,
        prev_blkid: Option<BlockId>,
        next_blkid: Option<BlockId>,
        trust: u64,
        height: u64,
    ) -> Self {
        Self {
            blkid,
            prev_blkid,
            next_blkid,
            trust,
            height,
        }
    }
}

pub const GENESIS: Block = Block {
    header: BlockHeader {
        id: 1337u64,
        prev_id: None,
    },
    transactions: vec![],
};

#[derive(Clone)]
pub struct Consensus {
    pub blks: Storage<Block>,
    pub blkidxs: Storage<BlockIndex>,
    pub highest_trust: u64,
    // TODO: don't store this here
    pub mainchain: BlockIndex,
    pub orphans: Vec<BlockId>,
}

// TODO: explain
fn find_common_ancestor<'a>(
    store: &Storage<Block>,
    loc: &mut impl Iterator<Item = &'a BlockHeader>,
    best: Option<Block>,
) -> Option<Block> {
    loc.next().map_or_else(
        || best.clone(),
        |hdr| {
            store
                .get(&hdr.id)
                .map(|our_blk| find_common_ancestor(store, loc, Some(our_blk.clone())))
                .map_or_else(|| best.clone(), |our_blk| our_blk)
        },
    )
}

impl Consensus {
    pub fn new() -> Self {
        let mut blkidxs = Storage::<BlockIndex>::new();
        let mut blks = Storage::<Block>::new();
        blks.add(GENESIS.header.id, GENESIS);

        let blkidx = BlockIndex::new(GENESIS.header.id, None, None, 20, 1);
        blkidxs.add(GENESIS.header.id, blkidx);

        Self {
            blks,
            blkidxs,
            highest_trust: 20,
            mainchain: blkidx,
            orphans: vec![],
        }
    }

    pub fn with_height(height: u64) -> Self {
        let mut blkidxs = Storage::<BlockIndex>::new();
        let mut blks = Storage::<Block>::new();

        let mut blk = GENESIS;
        let mut blkid = GENESIS.header.id;
        let mut blkidx = BlockIndex::new(GENESIS.header.id, None, None, 20, 1);
        let mut main: Option<BlockIndex> = None;

        blks.add(blkid, blk);
        blkidxs.add(blkid, blkidx);

        for i in 0..height {
            let blk = Block::new(Some(blkid));
            let cur_id = blk.header.id;
            let blkidx = blkidxs.get_mut(&blkid).unwrap();
            (*blkidx).next_blkid = Some(cur_id);
            let new_blkid = blk.header.id;
            let blkidx = BlockIndex::new(new_blkid, Some(blkid), None, 20 + 20 * (i + 1), 2 + i);

            blkid = new_blkid;
            blks.add(blkid, blk);
            blkidxs.add(blkid, blkidx);
            main = Some(blkidx);
        }

        Self {
            blks,
            blkidxs,
            highest_trust: (height + 1) * 20,
            mainchain: main.unwrap(),
            orphans: vec![],
        }
    }

    // walk from tip towards the genesis and collect block headers into a vector
    pub fn as_vec(&self) -> Vec<BlockHeader> {
        let mut res = vec![];
        let mut id: Option<BlockId> = Some(self.mainchain.blkid);

        loop {
            // more blocks?
            let id_u = match id {
                Some(id) => id,
                None => return res,
            };

            // get block header
            res.push(self.blks.get(&id_u).unwrap().header);

            // get next block index
            id = self.blkidxs.get(&id_u).unwrap().prev_blkid;
        }
    }

    // TODO: this doesn't work properly
    pub fn with_height_from_block(height: u64, id: BlockId, cons: &Consensus) -> Self {
        let mut blkidxs = Storage::<BlockIndex>::new();
        let mut blks = Storage::<Block>::new();
        let mut ret = cons.clone();

        let mut blkid = ret.mainchain.blkid;
        loop {
            if blkid == id {
                break;
            }

            ret.blkidxs.remove(&blkid);
            ret.blks.remove(&blkid);
            blkid = ret.mainchain.prev_blkid.unwrap();
        }

        let mut blkid = id;
        let old_height = ret.blkidxs.get(&id).unwrap().height;
        let mut old_trust = ret.blkidxs.get(&id).unwrap().trust + 20;
        let mut blkidx = BlockIndex::new(id, None, None, 0, 0);
        let mut main: Option<BlockIndex> = None;

        for i in (old_height + 1)..=(old_height + height) {
            let blk = Block::new(Some(blkid));
            let cur_id = blk.header.id;
            let blkidx = ret.blkidxs.get_mut(&blkid).unwrap();
            (*blkidx).next_blkid = Some(cur_id);
            let new_blkid = blk.header.id;
            let blkidx = BlockIndex::new(new_blkid, Some(blkid), None, old_trust, i);
            old_trust += 20;

            blkid = new_blkid;
            ret.blks.add(blkid, blk);
            ret.blkidxs.add(blkid, blkidx);
            main = Some(blkidx);
        }

        ret.highest_trust = main.unwrap().trust;
        ret.mainchain = main.unwrap();
        ret
    }

    fn active_best_chain(&mut self, other: &BlockIndex) -> Result<(), ()> {
        if other.height > self.mainchain.height {
            self.mainchain = *other;
            self.highest_trust = other.trust;
        }

        Ok(())
    }

    pub fn accept_block(&mut self, blk: Block) -> Result<(), ()> {
        // mainchain
        if blk.header.prev_id == Some(self.mainchain.blkid) {
            let prev = self.blkidxs.get_mut(&blk.header.prev_id.unwrap()).unwrap();
            (*prev).next_blkid = Some(blk.header.id);

            let blkidx = BlockIndex::new(
                blk.header.id,
                blk.header.prev_id,
                None,
                self.highest_trust + 20,
                prev.height + 1,
            );

            self.blkidxs.add(blk.header.id, blkidx);
            self.blks.add(blk.header.id, blk);
            self.mainchain = blkidx;
            self.highest_trust += 20;

            return Ok(());
        }

        // block not part of our mainchain
        let blkidx = match self.blkidxs.get_mut(&blk.header.prev_id.unwrap()) {
            Some(blkidx) => blkidx,
            None => {
                self.orphans.push(blk.header.id);
                self.blks.add(blk.header.id, blk);
                return Ok(());
            }
        };

        (*blkidx).next_blkid = Some(blk.header.id);

        let new_blkidx = BlockIndex::new(
            blk.header.id,
            Some(blkidx.blkid),
            None,
            blkidx.trust + 20,
            blkidx.height + 1,
        );

        self.blkidxs.add(blk.header.id, new_blkidx);
        self.blks.add(blk.header.id, blk);

        self.active_best_chain(&new_blkidx)
    }

    fn get_next_header(&self, left: isize, blkid: Option<&BlockId>) -> Option<BlockHeader> {
        blkid?;
        // if blkid.is_none() {
        //     return None;
        // }

        match self.blkidxs.get(blkid.unwrap()) {
            Some(v) => {
                if left == 0 {
                    return Some(self.blks.get(&v.blkid).unwrap().header);
                }

                return self.get_next_header(left - 1, v.prev_blkid.as_ref());
            }
            None => None,
        }
    }

    pub fn get_locator(&self) -> Vec<BlockHeader> {
        let mut headers = vec![];
        let mut index: isize = 1;

        while let Some(header) = self.get_next_header(index, Some(self.mainchain.blkid).as_ref()) {
            headers.push(header);
            index *= 2;
        }

        headers
    }

    pub fn get_headers(&self, locator: &[BlockHeader]) -> Vec<BlockHeader> {
        let mut id = find_common_ancestor(&self.blks, &mut locator.iter().rev(), None)
            .map_or_else(|| Some(GENESIS.header.id), |block| Some(block.header.id));

        let mut headers = vec![];
        while let Some(blkid) = id {
            headers.push(self.blks.get(&blkid).unwrap().header);
            id = self.blkidxs.get(&blkid).unwrap().next_blkid;
        }

        headers
    }

    pub fn get_uniq_headers(&self, headers: &[BlockHeader]) -> Vec<BlockHeader> {
        let mut ret = vec![];

        for header in headers {
            if self.blks.get(&header.id).is_none() {
                ret.push(*header);
            }
        }

        ret
    }

    pub fn get_blocks(&self, headers: &[BlockHeader]) -> Vec<Block> {
        headers.iter().map(|hdr| self.blks.get(&hdr.id).unwrap()).cloned().collect()
    }

    pub async fn start(&mut self, mut rx_p2p: mpsc::Receiver<ConsEvent>) {
        loop {
            match rx_p2p.recv().await.unwrap() {
                ConsEvent::GetLocator { response } => {
                    let locator = self.get_locator();
                    response.send(locator);
                }
                ConsEvent::NewBlock { block } => {
                    self.accept_block(block);
                }
                ConsEvent::GetUniqHeaders { headers, response } => {
                    let uniq_headers = self.get_uniq_headers(&headers);
                    response.send(uniq_headers);
                }
            }
        }
    }
}

pub enum ConsEvent {
    GetLocator {
        response: oneshot::Sender<Vec<BlockHeader>>,
    },
    NewBlock {
        block: Block,
    },
    GetUniqHeaders {
        headers: Vec<BlockHeader>,
        response: oneshot::Sender<Vec<BlockHeader>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_accept_block_mainchain() {
        let mut cons = Consensus::new();

        assert_eq!(cons.blks.store.len(), 1);
        assert_eq!(cons.blkidxs.store.len(), 1);

        let blkidx = cons.blkidxs.get(&GENESIS.header.id).unwrap();
        assert_eq!(blkidx.next_blkid, None);
        assert_eq!(blkidx.prev_blkid, None);
        assert_eq!(blkidx, &cons.mainchain);
        assert_eq!(blkidx.trust, 20);
        assert_eq!(blkidx.height, 1);

        let blk = Block::new(Some(GENESIS.header.id));
        let id = blk.header.id;
        assert_eq!(cons.accept_block(blk), Ok(()));

        assert_eq!(cons.blks.store.len(), 2);
        assert_eq!(cons.blkidxs.store.len(), 2);

        let blkidx = cons.blkidxs.get(&GENESIS.header.id).unwrap();
        assert_eq!(blkidx.next_blkid, Some(id));
        assert_eq!(blkidx.prev_blkid, None);
        assert_ne!(blkidx, &cons.mainchain);
        assert_eq!(blkidx.trust, 20);
        assert_eq!(blkidx.height, 1);

        let blkidx = cons.blkidxs.get(&id).unwrap();
        assert_eq!(blkidx.next_blkid, None);
        assert_eq!(blkidx.prev_blkid, Some(GENESIS.header.id));
        assert_eq!(blkidx, &cons.mainchain);
        assert_eq!(blkidx.trust, 40);
        assert_eq!(blkidx.height, 2);
    }

    #[test]
    fn test_accept_block_orphan() {
        let mut cons = Consensus::new();
        assert!(cons.orphans.is_empty());

        let blk = Block::new(Some(0x1337u64));
        assert_eq!(cons.accept_block(blk), Ok(()));
        assert_eq!(cons.orphans.len(), 1);
        assert!(cons.blks.get(&(1337u64)).is_some());
    }

    // verify that a chain of blocks is built correctly
    #[test]
    fn test_accept_block_chain() {
        let mut cons = Consensus::new();

        // add 3 blocks to the mainchain
        let blk1 = Block::new(Some(GENESIS.header.id));
        let id1 = blk1.header.id;

        let blk2 = Block::new(Some(id1));
        let id2 = blk2.header.id;

        let blk3 = Block::new(Some(id2));
        let id3 = blk3.header.id;

        assert_eq!(cons.accept_block(blk1), Ok(()));
        assert_eq!(cons.accept_block(blk2), Ok(()));
        assert_eq!(cons.accept_block(blk3), Ok(()));

        let blkidx = cons.blkidxs.get(&id3).unwrap();
        assert_eq!(blkidx.next_blkid, None);
        assert_eq!(blkidx.prev_blkid, Some(id2));
        assert_eq!(blkidx, &cons.mainchain);
        assert_eq!(blkidx.trust, 80);
        assert_eq!(blkidx.height, 4);

        let blkidx = cons.blkidxs.get(&id2).unwrap();
        assert_eq!(blkidx.next_blkid, Some(id3));
        assert_eq!(blkidx.prev_blkid, Some(id1));
        assert_eq!(blkidx.trust, 60);
        assert_eq!(blkidx.height, 3);

        let blkidx = cons.blkidxs.get(&id1).unwrap();
        assert_eq!(blkidx.next_blkid, Some(id2));
        assert_eq!(blkidx.prev_blkid, Some(GENESIS.header.id));
        assert_eq!(blkidx.trust, 40);
        assert_eq!(blkidx.height, 2);
    }

    // accept block to a fork but because the mainchain has higher trust,
    // it is kept as the mainchain after acceptance
    #[test]
    fn test_accept_block_fork() {
        let mut cons = Consensus::new();

        // add 3 blocks to the mainchain
        let blk1 = Block::new(Some(GENESIS.header.id));
        let id1 = blk1.header.id;

        let blk2 = Block::new(Some(id1));
        let id2 = blk2.header.id;

        let blk3 = Block::new(Some(id2));
        let id3 = blk3.header.id;

        assert_eq!(cons.accept_block(blk1), Ok(()));
        assert_eq!(cons.accept_block(blk2), Ok(()));
        assert_eq!(cons.accept_block(blk3), Ok(()));

        let blkidx = cons.blkidxs.get(&id3).unwrap();
        assert_eq!(cons.mainchain.trust, 80);
        assert_eq!(cons.mainchain.height, 4);
        assert_eq!(blkidx, &cons.mainchain);

        // add new block staring from block1 and verify that
        // it's added succesfully but mainchain is not updated
        let blk4 = Block::new(Some(id1));
        let id4 = blk4.header.id;

        assert_eq!(cons.accept_block(blk4), Ok(()));
        assert_eq!(cons.mainchain.trust, 80);
        assert_eq!(cons.mainchain.height, 4);

        let blkidx = cons.blkidxs.get(&id4).unwrap();
        assert_eq!(blkidx.next_blkid, None);
        assert_eq!(blkidx.prev_blkid, Some(id1));
        assert_eq!(blkidx.trust, 60);
        assert_eq!(blkidx.height, 3);
    }

    // accept block to a fork and because after acceptance the fork has higher
    // trust, it is marked as the new mainchain
    #[test]
    fn test_accept_block_fork_switch_chains() {
        let mut cons = Consensus::new();

        // add 3 blocks to the mainchain
        let blk1 = Block::new(Some(GENESIS.header.id));
        let id1 = blk1.header.id;

        let blk2 = Block::new(Some(id1));
        let id2 = blk2.header.id;

        let blk3 = Block::new(Some(id2));
        let id3 = blk3.header.id;

        assert_eq!(cons.accept_block(blk1), Ok(()));
        assert_eq!(cons.accept_block(blk2), Ok(()));
        assert_eq!(cons.accept_block(blk3), Ok(()));
        assert_eq!(cons.mainchain.trust, 80);
        assert_eq!(cons.mainchain.height, 4);

        // add new block staring from block1 and verify that
        // it's added succesfully but mainchain is not updated
        let blk4 = Block::new(Some(id1));
        let id4 = blk4.header.id;

        let blk5 = Block::new(Some(id4));
        let id5 = blk5.header.id;

        let blk6 = Block::new(Some(id5));
        let id6 = blk6.header.id;

        assert_eq!(cons.accept_block(blk4), Ok(()));
        assert_eq!(cons.accept_block(blk5), Ok(()));
        assert_eq!(cons.accept_block(blk6), Ok(()));

        assert_eq!(cons.mainchain.trust, 100);
        assert_eq!(cons.mainchain.height, 5);

        let blkidx = cons.blkidxs.get(&id6).unwrap();
        assert_eq!(blkidx, &cons.mainchain);
        assert_eq!(blkidx.next_blkid, None);
        assert_eq!(blkidx.prev_blkid, Some(id5));
        assert_eq!(blkidx.trust, 100);
        assert_eq!(blkidx.height, 5);
    }

    #[test]
    fn test_with_height() {
        let mut cons = Consensus::with_height(3);

        assert_eq!(cons.blks.store.len(), 4);
        assert_eq!(cons.blkidxs.store.len(), 4);

        let blkidx = cons.blkidxs.get(&GENESIS.header.id).unwrap();
        assert!(blkidx.next_blkid.is_some());
        assert_eq!(blkidx.prev_blkid, None);
        assert_eq!(blkidx.trust, 20);
        assert_eq!(blkidx.height, 1);

        let prev_id = blkidx.blkid;
        let blkidx = cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
        assert!(blkidx.next_blkid.is_some());
        assert_eq!(blkidx.prev_blkid, Some(prev_id));
        assert_eq!(blkidx.trust, 40);
        assert_eq!(blkidx.height, 2);

        let prev_id = blkidx.blkid;
        let blkidx = cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
        assert!(blkidx.next_blkid.is_some());
        assert_eq!(blkidx.prev_blkid, Some(prev_id));
        assert_eq!(blkidx.trust, 60);
        assert_eq!(blkidx.height, 3);

        let prev_id = blkidx.blkid;
        let blkidx = cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
        assert!(blkidx.next_blkid.is_none());
        assert_eq!(blkidx.prev_blkid, Some(prev_id));
        assert_eq!(blkidx.trust, 80);
        assert_eq!(blkidx.height, 4);
        assert_eq!(&cons.mainchain, blkidx);
    }

    #[test]
    fn test_with_height_from() {
        let mut cons = Consensus::with_height(3);
        let id = cons.mainchain.prev_blkid.unwrap();
        let mut new_cons = Consensus::with_height_from_block(2, id, &cons);

        assert_eq!(new_cons.blks.store.len(), 5);
        assert_eq!(new_cons.blkidxs.store.len(), 5);

        let blkidx = new_cons.blkidxs.get(&id).unwrap();
        assert!(blkidx.next_blkid.is_some());
        assert_eq!(blkidx.trust, 60);
        assert_eq!(blkidx.height, 3);

        let prev_id = blkidx.blkid;
        let blkidx = new_cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
        assert!(blkidx.next_blkid.is_some());
        assert_eq!(blkidx.prev_blkid, Some(id));
        assert_eq!(blkidx.trust, 80);
        assert_eq!(blkidx.height, 4);

        let prev_id = blkidx.blkid;
        let blkidx = new_cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
        assert!(blkidx.next_blkid.is_none());
        assert_eq!(blkidx.prev_blkid, Some(prev_id));
        assert_eq!(blkidx.trust, 100);
        assert_eq!(blkidx.height, 5);
    }

    #[test]
    fn test_as_vec() {
        let mut cons = Consensus::with_height(15);
        let headers = cons.as_vec();

        assert_eq!(cons.blks.store.len(), 16);
        assert_eq!(cons.blkidxs.store.len(), 16);

        let mut blk = cons.blks.get(&GENESIS.header.id).unwrap();
        let mut blkidx = cons.blkidxs.get(&GENESIS.header.id).unwrap();
        assert_eq!(headers[15], blk.header);

        for i in (0..cons.blkidxs.store.len() - 1).rev() {
            blk = cons.blks.get(&blkidx.next_blkid.unwrap()).unwrap();
            blkidx = cons.blkidxs.get(&blkidx.next_blkid.unwrap()).unwrap();
            assert_eq!(headers[i], blk.header);
        }
    }

    #[test]
    fn test_locator_1() {
        let mut cons = Consensus::with_height(8);
        let headers = cons.as_vec();
        let locator = cons.get_locator();
        assert_eq!(
            locator,
            vec![headers[1], headers[2], headers[4], headers[8],]
        );
    }

    #[test]
    fn test_locator_1000() {
        let mut cons = Consensus::with_height(1000);
        let headers = cons.as_vec();
        let locator = cons.get_locator();

        assert_eq!(
            locator,
            vec![
                headers[1],
                headers[2],
                headers[4],
                headers[8],
                headers[16],
                headers[32],
                headers[64],
                headers[128],
                headers[256],
                headers[512],
            ]
        );
    }

    #[test]
    fn test_find_common_ancestor_self() {
        let mut rng = rand::thread_rng();

        for i in 0..20 {
            let height: u64 = rng.gen_range(8..128);

            let mut cons = Consensus::with_height(height);
            let headers = cons.as_vec();
            let locator = cons.get_locator();

            assert_eq!(
                find_common_ancestor(&cons.blks, &mut locator.iter().rev(), None)
                    .unwrap()
                    .header,
                headers[1],
            );
        }
    }

    // chains don't share any common blocks apart from genesis
    #[test]
    fn test_find_common_ancestor_fork_only_genesis() {
        let mut cons1 = Consensus::with_height(8);
        let mut cons2 = Consensus::with_height(8);

        let headers = cons2.as_vec();
        let locator = cons1.get_locator();

        assert_eq!(
            find_common_ancestor(&cons2.blks, &mut locator.iter().rev(), None)
                .unwrap()
                .header,
            headers[headers.len() - 1],
        );

        let mut cons1 = Consensus::with_height(15);
        let mut cons2 = Consensus::with_height(15);

        let headers = cons2.as_vec();
        let locator = cons1.get_locator();

        assert_eq!(
            find_common_ancestor(&cons2.blks, &mut locator.iter().rev(), None),
            None,
        );

        let mut cons1 = Consensus::with_height(4);
        let mut cons2 = Consensus::with_height(4);

        let headers = cons2.as_vec();
        let locator = cons1.get_locator();

        assert_eq!(
            find_common_ancestor(&cons2.blks, &mut locator.iter().rev(), None)
                .unwrap()
                .header,
            headers[headers.len() - 1],
        );

        let mut cons1 = Consensus::with_height(127);
        let mut cons2 = Consensus::with_height(127);

        let headers = cons2.as_vec();
        let locator = cons1.get_locator();

        assert_eq!(
            find_common_ancestor(&cons2.blks, &mut locator.iter().rev(), None),
            None,
        );
    }

    // cons2 contains more blocks than cons1 but
    #[test]
    fn test_find_common_ancestor_updated_mainchain() {
        let mut rng = rand::thread_rng();

        for i in 0..20 {
            let height: u64 = rng.gen_range(8..128);
            let additional: u64 = rng.gen_range(8..128);

            let mut cons1 = Consensus::with_height(height);
            let id = cons1.mainchain.prev_blkid.unwrap();
            let mut cons2 = Consensus::with_height_from_block(additional, id, &cons1);

            let headers = cons2.as_vec();
            let loc_cons1 = cons1.get_locator();

            assert_eq!(
                find_common_ancestor(&cons2.blks, &mut loc_cons1.iter().rev(), None)
                    .unwrap()
                    .header,
                headers[additional as usize]
            );
        }
    }

    #[test]
    fn test_get_headers() {
        let mut rng = rand::thread_rng();

        for i in 0..20 {
            let height: u64 = rng.gen_range(8..128);
            let mut cons = Consensus::with_height(height);
            let headers: Vec<BlockHeader> = cons.as_vec().into_iter().rev().collect();
            let loc = cons.get_locator();
            let fetched = cons.get_headers(&loc);

            assert_eq!(fetched, headers[headers.len() - 2..],);
        }
    }

    // create chain with random length and take the locator object of that chain
    // which represents an out-of-sync chain. Then add more blocks to the chain
    // and use the "old chain's" locator object to request more headers
    #[test]
    fn test_get_headers_old_chain_syncing_to_new() {
        let mut rng = rand::thread_rng();

        for i in 0..20 {
            let height: u64 = rng.gen_range(8..128);
            let mut cons = Consensus::with_height(height);
            let mut prev_id = cons.mainchain.blkid;
            let loc = cons.get_locator();

            let new_blocks: Vec<BlockHeader> = (0..rng.gen_range(8..128))
                .map(|_| {
                    let blk = Block::new(Some(prev_id));
                    assert!(cons.accept_block(blk.clone()).is_ok());
                    prev_id = blk.header.id;
                    blk.header
                })
                .collect::<_>();

            let fetched = cons.get_headers(&loc);
            let headers: Vec<BlockHeader> = cons.as_vec().into_iter().rev().collect();

            assert_eq!(fetched, headers[(height as usize) - 1..]);
        }
    }

    #[test]
    fn test_get_headers_forks() {
        let mut cons1 = Consensus::with_height(7);
        let id = cons1.mainchain.prev_blkid.unwrap();
        let mut cons2 = Consensus::with_height_from_block(3, id, &cons1);

        // current chains
        //
        // A-B-C-D-E-F-G-H
        //               |-I-J-K

        let mut prev_id = cons1.mainchain.blkid;
        let cons1_new_blocks: Vec<BlockHeader> = (0..2)
            .map(|_| {
                let blk = Block::new(Some(prev_id));
                assert!(cons1.accept_block(blk.clone()).is_ok());
                prev_id = blk.header.id;
                blk.header
            })
            .collect::<_>();

        // current chains
        //
        //    		     |-L-M
        // A-B-C-D-E-F-G-H
        //               |-I-J-K

        let mut prev_id = cons2.mainchain.blkid;
        let cons2_new_blocks: Vec<BlockHeader> = (0..2)
            .map(|_| {
                let blk = Block::new(Some(prev_id));
                assert!(cons2.accept_block(blk.clone()).is_ok());
                prev_id = blk.header.id;
                blk.header
            })
            .collect::<_>();

        // current chains
        //
        //    		     |-L-M
        // A-B-C-D-E-F-G-H
        //               |-I-J-K-N-O
        //
        // cons1 (left side) requesting blocks from cons2
        // should get the common ancestor G and all the blocks from H to O
        let loc_cons1 = cons1.get_locator();
        let requested = cons2.get_headers(&loc_cons1);
        let hdrs_cons2: Vec<BlockHeader> = cons2.as_vec().into_iter().rev().collect();

        assert_eq!(requested.len(), 7);
        assert_eq!(requested, hdrs_cons2[hdrs_cons2.len() - 7..]);
    }

    #[test]
    fn test_get_uniq_headers() {
        let mut cons = Consensus::with_height(7);
        let mut prev_id = cons.mainchain.blkid;
        let mut new_headers: Vec<BlockHeader> = (0..3)
            .map(|_| {
                let blk = Block::new(Some(prev_id));
                prev_id = blk.header.id;
                blk.header
            })
            .collect::<_>();

        new_headers.push(GENESIS.header);
        assert_eq!(new_headers.len(), 4);

        let uniq = cons.get_uniq_headers(&new_headers);
        assert_eq!(uniq.len(), 3);
        assert_eq!(uniq, new_headers[..new_headers.len() - 1]);
    }
}
