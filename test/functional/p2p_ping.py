#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ping message
"""

import time

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PING_INTERVAL = 60
TIMEOUT_INTERVAL = 150


class NodeNoPong(P2PInterface):
    def on_ping(self, message):
        pass


class PingPongTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            '--p2p-ping-timeout={}'.format(TIMEOUT_INTERVAL),
            '--p2p-ping-check-period={}'.format(PING_INTERVAL),
            '--p2p-disable-noise=true'
        ]]

    def check_peer_info(self, *, ping_last, ping_min, ping_wait):
        stats = self.nodes[0].p2p_get_connected_peers()[0]
        assert_equal(stats.pop('ping_last', None), ping_last)
        assert_equal(stats.pop('ping_min', None), ping_min)
        assert_equal(stats.pop('ping_wait', None), ping_wait)

    def mock_forward(self, delta):
        self.mock_time += delta
        self.nodes[0].node_set_mock_time(self.mock_time)

    def run_test(self):
        self.mock_time = int(time.time())
        self.mock_forward(0)

        self.log.info(
            'Check that ping is sent after connection is established')
        no_pong_node = self.nodes[0].add_p2p_connection(NodeNoPong())
        # Wake up event loop to send pings as needed
        self.mock_forward(PING_INTERVAL + 5)
        no_pong_node.sync_with_ping()

        # Ping wait time should be 3 seconds now
        self.mock_forward(3)
        no_pong_node.sync_with_ping()
        nonce = no_pong_node.last_message.pop('ping_request')['nonce']
        self.check_peer_info(ping_last=None, ping_min=None, ping_wait=3000)

        # Send ping response normally
        no_pong_node.send_and_ping({
            "ping_response": {
                "nonce": nonce,
            }
        })
        self.check_peer_info(ping_last=3000, ping_min=3000, ping_wait=None)

        self.log.info('Reply without ping')
        with self.nodes[0].assert_debug_log([
                'unexpected ping response received from peer 1',
        ]):
            no_pong_node.send_and_ping({
                "ping_response": {
                    "nonce": 12345,
                }
            })
        self.check_peer_info(ping_last=3000, ping_min=3000, ping_wait=None)

        self.log.info('Reply with wrong nonce does not cancel ping')
        assert 'ping_request' not in no_pong_node.last_message
        with self.nodes[0].assert_debug_log(['wrong nonce in ping response from peer 1']):
            # mock time PING_INTERVAL ahead to trigger node into sending a ping
            self.mock_forward(PING_INTERVAL)
            no_pong_node.wait_until(
                lambda: 'ping_request' in no_pong_node.last_message)
            self.mock_forward(9)
            # Send the wrong pong
            no_pong_node.send_and_ping({
                "ping_response": {
                    "nonce": 12345,
                }
            })
        self.check_peer_info(ping_last=3000, ping_min=3000, ping_wait=9000)

        self.log.info('Check that ping_min and ping_last updated as expected')
        nonce = no_pong_node.last_message.pop('ping_request')['nonce']
        # Send ping response
        no_pong_node.send_and_ping({
            "ping_response": {
                "nonce": nonce,
            }
        })
        self.check_peer_info(ping_last=9000, ping_min=3000, ping_wait=None)

        self.log.info('Check that peer is disconnected after ping timeout')
        assert 'ping_request' not in no_pong_node.last_message
        self.mock_forward(PING_INTERVAL)
        no_pong_node.wait_until(lambda: 'ping_request' in no_pong_node.last_message)
        with self.nodes[0].assert_debug_log(['ping check: dead peer detected: 1']):
            self.mock_forward(TIMEOUT_INTERVAL)
        no_pong_node.wait_for_disconnect()


if __name__ == '__main__':
    PingPongTest().main()
