#!/usr/bin/env python3
"""Mempool reorg test

Check that:
* Transactions are collected into blocks when a new block is issued.
* Transactions are correctly put back into mempool when the block is reorged out.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework import mintlayer_hash
import scalecodec
import time

base_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('TransactionV1')
block_header_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('BlockHeader')
block_input_data_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('GenerateBlockInputData')
block_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('BlockV1')
signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction')
vec_output_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('Vec<TxOutput>')

def hash_object(obj, data):
    return scalecodec.ScaleBytes(mintlayer_hash(obj.encode(data).data)).to_hex()[2:]

def reward_input(block_id, index = 0):
    return {
        'id': { 'BlockReward': '0x{}'.format(block_id) },
        'index': index,
    }

def tx_input(tx_id, index = 0):
    return {
        'id': { 'Transaction': '0x{}'.format(tx_id) },
        'index': index,
    }

def make_tx(inputs, output_amounts, flags = 0):
    outputs = [ {'Transfer': [ { 'Coin': amt }, { 'AnyoneCanSpend': None } ]}
               for amt in output_amounts ]
    witness = { 'NoSignature': None }
    tx = {
        'version': 1,
        'flags': flags,
        'inputs': inputs,
        'outputs': outputs,
    }
    signed_tx = {
        'transaction': tx,
        'signatures': [witness for _ in outputs],
    }
    tx_id = hash_object(base_tx_obj, tx)
    encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
    return (encoded_tx, tx_id)

def make_empty_block(parent_id, nonce, transactions = []):
    empty_merkle_root = "0x" + hash_object(vec_output_obj, [])
    pow_data = {
        'bits': 0x207fffff,
        'nonce': nonce,
    }
    header = {
        'version': 1,
        'prev_block_id': "0x{}".format(parent_id),
        'tx_merkle_root': empty_merkle_root,
        'witness_merkle_root': empty_merkle_root,
        'timestamp': int(time.time()),
        'consensus_data': { 'PoW': pow_data },
    }
    signed_header = {
        'header': header,
        'signature': { 'None': None },
    }
    block = {
        'header': signed_header,
        'reward': [],
        'transactions': transactions,
    }
    block_id = hash_object(block_header_obj, header)
    encoded_block = block_obj.encode(block).to_hex()[2:]
    return (encoded_block, block_id)

def mine_empty_block(parent_id):
    for nonce in range(1000):
        (block, block_id) = make_empty_block(parent_id, nonce)
        if block_id[-2] in "0123456":
            return (block, block_id)
    assert False, "Cannot mine block"

class MempoolTxSubmissionTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def run_test(self):
        node = self.nodes[0]

        # Get chain tip
        genesis_id = node.chainstate_best_block_id()
        self.log.debug('Initial tip: {}'.format(genesis_id))

        # Prepare three transactions, each spending the previous one in sequence
        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 1_000_000 ] )
        self.log.debug("Encoded tx1 {}: {}".format(tx1_id, tx1))
        (tx2, tx2_id) = make_tx([ tx_input(tx1_id) ], [ 900_000 ] )
        self.log.debug("Encoded tx2 {}: {}".format(tx2_id, tx2))
        (tx3, tx3_id) = make_tx([ tx_input(tx2_id) ], [ 800_000 ] )
        self.log.debug("Encoded tx3 {}: {}".format(tx3_id, tx3))

        # Submit the first transaction
        node.mempool_submit_transaction(tx1)
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block1 = node.blockprod_generate_block(block_input_data, [tx1])
        node.chainstate_submit_block(block1)
        block1_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block1_id, timeout = 5)
        assert not node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Submit the other two transactions
        node.mempool_submit_transaction(tx2)
        node.mempool_submit_transaction(tx3)
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

        # Submit a block with the other two transactions
        block2 = node.blockprod_generate_block(block_input_data, [tx2, tx3])
        node.chainstate_submit_block(block2)
        block2_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block2_id, timeout = 5)
        assert not node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Create two new blocks on top of block1
        (block2a, block2a_id) = mine_empty_block(block1_id)
        (block3a, block3a_id) = mine_empty_block(block2a_id)
        self.log.debug("Encoded block2a {}: {}".format(block2a_id, block2a))
        self.log.debug("Encoded block3a {}: {}".format(block3a_id, block3a))

        # Submit the two blocks and verify block3a in the new tip
        node.chainstate_submit_block(block2a)
        node.chainstate_submit_block(block3a)
        self.wait_until(lambda: node.mempool_local_best_block_id() == block3a_id, timeout = 5)

        # Check transactions from disconnected blocks are back in the mempool
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

if __name__ == '__main__':
    MempoolTxSubmissionTest().main()
