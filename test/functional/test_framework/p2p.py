#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test objects for interacting with a bitcoind node over the p2p protocol.

The P2PInterface objects interact with the bitcoind nodes under test using the
node's p2p interface. They can be used to send messages to the node, and
callbacks can be registered that execute when messages are received from the
node. Messages are sent to/received from the node on an asyncio event loop.
State held inside the objects must be guarded by the p2p_lock to avoid data
races between the main testing thread and the event loop.

P2PConnection: A low-level connection object to a node's P2P interface
P2PInterface: A high-level interface object for communicating to a node over P2P
P2PDataStore: A p2p interface class that keeps a store of transactions and blocks
              and can respond correctly to getdata and getheaders messages
P2PTxInvStore: A p2p interface class that inherits from P2PDataStore, and keeps
              a count of how many times each txid has been announced."""

import asyncio
from collections import defaultdict
import logging
import struct
import sys
import threading
import scalecodec
import time

from test_framework.messages import (
    CBlockHeader,
    MAX_HEADERS_RESULTS,
    msg_addr,
    msg_addrv2,
    msg_block,
    MSG_BLOCK,
    msg_blocktxn,
    msg_cfcheckpt,
    msg_cfheaders,
    msg_cfilter,
    msg_cmpctblock,
    msg_feefilter,
    msg_filteradd,
    msg_filterclear,
    msg_filterload,
    msg_getaddr,
    msg_getblocks,
    msg_getblocktxn,
    msg_getdata,
    msg_getheaders,
    msg_headers,
    msg_inv,
    msg_mempool,
    msg_merkleblock,
    msg_notfound,
    msg_ping,
    msg_pong,
    msg_sendaddrv2,
    msg_sendcmpct,
    msg_sendheaders,
    msg_tx,
    MSG_TX,
    MSG_TYPE_MASK,
    msg_verack,
    msg_version,
    MSG_WTX,
    msg_wtxidrelay,
    sha256,
)
from test_framework.util import (
    MAX_NODES,
    p2p_port,
    wait_until_helper,
)
from test_framework.mintlayer import (
    calc_tx_id,
)

logger = logging.getLogger("TestFramework.p2p")

P2P_NETWORK_PROTOCOL = 1

# The P2P user agent string that this test framework sends in its `handshake` message
P2P_USER_AGENT = "PythonTesterP2P"

SERVICE_TRANSACTIONS = 1 << 0
SERVICE_BLOCKS = 1 << 1
SERVICE_PEER_ADDRESSES = 1 << 2

# The services that this test framework offers in its `handshake` message
P2P_SERVICES = SERVICE_TRANSACTIONS | SERVICE_BLOCKS | SERVICE_PEER_ADDRESSES

# Maximum message size
MAX_MESSAGE_SIZE = 10 * 1024 * 1024

MESSAGEMAP = {
    b"addr": msg_addr,
    b"addrv2": msg_addrv2,
    b"block": msg_block,
    b"blocktxn": msg_blocktxn,
    b"cfcheckpt": msg_cfcheckpt,
    b"cfheaders": msg_cfheaders,
    b"cfilter": msg_cfilter,
    b"cmpctblock": msg_cmpctblock,
    b"feefilter": msg_feefilter,
    b"filteradd": msg_filteradd,
    b"filterclear": msg_filterclear,
    b"filterload": msg_filterload,
    b"getaddr": msg_getaddr,
    b"getblocks": msg_getblocks,
    b"getblocktxn": msg_getblocktxn,
    b"getdata": msg_getdata,
    b"getheaders": msg_getheaders,
    b"headers": msg_headers,
    b"inv": msg_inv,
    b"mempool": msg_mempool,
    b"merkleblock": msg_merkleblock,
    b"notfound": msg_notfound,
    b"ping": msg_ping,
    b"pong": msg_pong,
    b"sendaddrv2": msg_sendaddrv2,
    b"sendcmpct": msg_sendcmpct,
    b"sendheaders": msg_sendheaders,
    b"tx": msg_tx,
    b"verack": msg_verack,
    b"version": msg_version,
    b"wtxidrelay": msg_wtxidrelay,
}

MAGIC_BYTES = {
    "mainnet": b"\xf9\xbe\xb4\xd9",   # mainnet
    "testnet3": b"\x0b\x11\x09\x07",  # testnet3
    "regtest": b"\xfa\xbf\xb5\xda",   # regtest
    "signet": b"\x0a\x03\xcf\x40",    # signet
}


class P2PConnection(asyncio.Protocol):
    """A low-level connection object to a node's P2P interface.

    This class is responsible for:

    - opening and closing the TCP connection to the node
    - reading bytes from and writing bytes to the socket
    - deserializing and serializing the P2P message header
    - logging messages as they are sent and received

    This class contains no logic for handing the P2P message payloads. It must be
    sub-classed and the on_message() callback overridden."""

    def __init__(self):
        # The underlying transport of the connection.
        # Should only call methods on this from the NetworkThread, c.f. call_soon_threadsafe
        self._transport = None

    @property
    def is_connected(self):
        return self._transport is not None

    def peer_connect_helper(self, dstaddr, dstport, net, timeout_factor):
        assert not self.is_connected
        self.timeout_factor = timeout_factor
        self.dstaddr = dstaddr
        self.dstport = dstport
        # The initial message to send after the connection was made:
        self.on_connection_send_msg = None
        self.recvbuf = b""
        self.magic_bytes = MAGIC_BYTES[net]

    def peer_connect(self, dstaddr, dstport, *, net, timeout_factor):
        self.peer_connect_helper(dstaddr, dstport, net, timeout_factor)

        loop = NetworkThread.network_event_loop
        logger.debug('Connecting to Bitcoin Node: %s:%d' % (self.dstaddr, self.dstport))
        coroutine = loop.create_connection(lambda: self, host=self.dstaddr, port=self.dstport)
        return lambda: loop.call_soon_threadsafe(loop.create_task, coroutine)

    def peer_accept_connection(self, connect_id, connect_cb=lambda: None, *, net, timeout_factor):
        self.peer_connect_helper('0', 0, net, timeout_factor)

        logger.debug('Listening for Bitcoin Node with id: {}'.format(connect_id))
        return lambda: NetworkThread.listen(self, connect_cb, idx=connect_id)

    def peer_disconnect(self):
        # Connection could have already been closed by other end.
        NetworkThread.network_event_loop.call_soon_threadsafe(lambda: self._transport and self._transport.abort())

    # Connection and disconnection methods

    def connection_made(self, transport):
        """asyncio callback when a connection is opened."""
        assert not self._transport
        logger.debug("Connected & Listening: %s:%d" % (self.dstaddr, self.dstport))
        self._transport = transport
        if self.on_connection_send_msg:
            self.send_message(self.on_connection_send_msg)
            self.on_connection_send_msg = None  # Never used again
        self.on_open()

    def connection_lost(self, exc):
        """asyncio callback when a connection is closed."""
        if exc:
            logger.warning("Connection lost to {}:{} due to {}".format(self.dstaddr, self.dstport, exc))
        else:
            logger.debug("Closed connection to: %s:%d" % (self.dstaddr, self.dstport))
        self._transport = None
        self.recvbuf = b""
        self.on_close()

    # Socket read methods

    def data_received(self, t):
        """asyncio callback when data is read from the socket."""
        if len(t) > 0:
            self.recvbuf += t
            self._on_data()

    def _on_data(self):
        """Try to read P2P messages from the recv buffer.

        This method reads data from the buffer in a loop. It deserializes,
        parses and verifies the P2P header, then passes the P2P payload to
        the on_message callback for processing."""
        try:
            while True:
                # Wait for the message length header first
                if len(self.recvbuf) < 4:
                    return
                msglen = struct.unpack("<I", self.recvbuf[0:4])[0]
                if msglen > MAX_MESSAGE_SIZE:
                    raise AssertionError("Frame of length {} is too large".format(MAX_MESSAGE_SIZE))
                # Wait for the full message
                if len(self.recvbuf) < 4 + msglen:
                    return
                data = self.recvbuf[4:4 + msglen]
                self.recvbuf = self.recvbuf[4 + msglen:]

                obj = scalecodec.base.RuntimeConfiguration().create_scale_object("Message")
                # This will throw if the data has any bytes left.
                # Check that `init_p2p_types` has the correct type declarations if decoding fails.
                t = obj.decode(scalecodec.ScaleBytes(data))

                self._log_message("receive", t)
                self.on_message(t)
        except Exception as e:
            logger.exception('Error reading message:', repr(e))
            raise

    def on_message(self, message):
        """Callback for processing a P2P payload. Must be overridden by derived class."""
        raise NotImplementedError

    # Socket write methods

    def send_message(self, message):
        """Send a P2P message over the socket.

        This method takes a P2P payload, builds the P2P header and adds
        the message to the send buffer to be sent over the socket."""
        tmsg = self.build_message(message)
        self._log_message("send", message)
        return self.send_raw_message(tmsg)

    def send_raw_message(self, raw_message_bytes):
        if not self.is_connected:
            raise IOError('Not connected')

        def maybe_write():
            if not self._transport:
                return
            if self._transport.is_closing():
                return
            self._transport.write(raw_message_bytes)
        NetworkThread.network_event_loop.call_soon_threadsafe(maybe_write)

    # Class utility methods

    def build_message(self, message):
        """Build a serialized P2P message"""
        obj = scalecodec.base.RuntimeConfiguration().create_scale_object("Message")
        data = obj.encode(message)

        # Prepend message length (little-endian u32)
        tmsg = struct.pack("<I", len(data))
        tmsg += data.data
        return tmsg

    def _log_message(self, direction, msg):
        """Logs a message being sent or received over the connection."""
        if direction == "send":
            log_message = "Send message to "
        elif direction == "receive":
            log_message = "Received message from "
        log_message += "%s:%d: %s" % (self.dstaddr, self.dstport, repr(msg)[:500])
        if len(log_message) > 500:
            log_message += "... (msg truncated)"
        logger.debug(log_message)


class P2PInterface(P2PConnection):
    """A high-level P2P interface class for communicating with a Bitcoin node.

    This class provides high-level callbacks for processing P2P message
    payloads, as well as convenience methods for interacting with the
    node over P2P.

    Individual testcases should subclass this and override the on_* methods
    if they want to alter message handling behaviour."""
    def __init__(self, support_addrv2=False, wtxidrelay=True):
        super().__init__()

        # Track number of messages of each type received.
        # Should be read-only in a test.
        self.message_count = defaultdict(int)

        # Track the most recent message of each type.
        # To wait for a message to be received, pop that message from
        # this and use self.wait_until.
        self.last_message = {}

        # A count of the number of ping messages we've sent to the node
        self.ping_counter = 1

        # The network services received from the peer
        self.services = 0

        self.support_addrv2 = support_addrv2

        # If the peer supports wtxid-relay
        self.wtxidrelay = wtxidrelay

    def peer_connect_send_handshake(self, services):
        # Send a handshake msg
        vt = {
            "handshake": {
                "Hello": {
                    "protocol": P2P_NETWORK_PROTOCOL,
                    "network": [0xaa, 0xbb, 0xcc, 0xdd],
                    "services": services,
                    "user_agent": P2P_USER_AGENT,
                    "version": {
                        "major": 0,
                        "minor": 1,
                        "patch": 0,
                    },
                    "receiver_address": None,
                    "current_time": int(time.time()),
                    "handshake_nonce": 123,
                }
            }
        }
        self.on_connection_send_msg = vt  # Will be sent in connection_made callback

    def peer_connect(self, *args, services=P2P_SERVICES, send_version=True, **kwargs):
        create_conn = super().peer_connect(*args, **kwargs)

        if send_version:
            self.peer_connect_send_handshake(services)

        return create_conn

    def peer_accept_connection(self, *args, services=P2P_SERVICES, **kwargs):
        create_conn = super().peer_accept_connection(*args, **kwargs)
        self.peer_connect_send_handshake(services)

        return create_conn

    # Message receiving methods

    def on_message(self, message):
        """Receive message and dispatch message to appropriate callback.

        We keep a count of how many of each message type has been received
        and the most recent message of each type."""
        with p2p_lock:
            try:
                # Get message type from the first key (for example "ping_request")
                msgtype = next(iter(message))
                self.message_count[msgtype] += 1
                # Store message body
                self.last_message[msgtype] = message[msgtype]
                getattr(self, 'on_' + msgtype)(message)
            except:
                print("ERROR delivering %s (%s)" % (repr(message), sys.exc_info()[0]))
                raise

    # Callback methods. Can be overridden by subclasses in individual test
    # cases to provide custom message handling behaviour.

    def on_open(self):
        pass

    def on_close(self):
        pass

    def on_handshake(self, message):
        self.services = message["handshake"]["HelloAck"]["services"]

    def on_ping_request(self, message): pass
    def on_ping_response(self, message): pass
    def on_header_list_request(self, message): pass

    # Not used:
    # def on_addr(self, message): pass
    # def on_addrv2(self, message): pass
    # def on_block(self, message): pass
    # def on_blocktxn(self, message): pass
    # def on_cfcheckpt(self, message): pass
    # def on_cfheaders(self, message): pass
    # def on_cfilter(self, message): pass
    # def on_cmpctblock(self, message): pass
    # def on_feefilter(self, message): pass
    # def on_filteradd(self, message): pass
    # def on_filterclear(self, message): pass
    # def on_filterload(self, message): pass
    # def on_getaddr(self, message): pass
    # def on_getblocks(self, message): pass
    # def on_getblocktxn(self, message): pass
    # def on_getdata(self, message): pass
    # def on_getheaders(self, message): pass
    # def on_headers(self, message): pass
    # def on_mempool(self, message): pass
    # def on_merkleblock(self, message): pass
    # def on_notfound(self, message): pass
    # def on_pong(self, message): pass
    # def on_sendaddrv2(self, message): pass
    # def on_sendcmpct(self, message): pass
    # def on_sendheaders(self, message): pass
    # def on_tx(self, message): pass
    # def on_wtxidrelay(self, message): pass

    def on_inv(self, message):
        want = msg_getdata()
        for i in message.inv:
            if i.type != 0:
                want.inv.append(i)
        if len(want.inv):
            self.send_message(want)

    def on_ping(self, message):
        self.send_message({
            "ping_response": {
                "nonce": message['nonce'],
                }
            }
        )

    # def on_version(self, message):
    #     assert message.nVersion >= MIN_P2P_VERSION_SUPPORTED, "Version {} received. Test framework only supports versions greater than {}".format(message.nVersion, MIN_P2P_VERSION_SUPPORTED)
    #     if message.nVersion >= 70016 and self.wtxidrelay:
    #         self.send_message(msg_wtxidrelay())
    #     if self.support_addrv2:
    #         self.send_message(msg_sendaddrv2())
    #     self.send_message(msg_verack())
    #     self.nServices = message.nServices
    #     self.send_message(msg_getaddr())

    # Connection helper methods

    def wait_until(self, test_function_in, *, timeout=60, check_connected=True):
        def test_function():
            if check_connected:
                assert self.is_connected
            return test_function_in()

        wait_until_helper(test_function, timeout=timeout, lock=p2p_lock, timeout_factor=self.timeout_factor)

    def wait_for_connect(self, timeout=60):
        test_function = lambda: self.is_connected
        wait_until_helper(test_function, timeout=timeout, lock=p2p_lock)

    def wait_for_disconnect(self, timeout=60):
        test_function = lambda: not self.is_connected
        self.wait_until(test_function, timeout=timeout, check_connected=False)

    # Message receiving helper methods

    def wait_for_tx(self, txid, timeout=60):
        def test_function():
            if not self.last_message.get('tx'):
                return False
            return self.last_message['tx'].tx.rehash() == txid

        self.wait_until(test_function, timeout=timeout)

    def wait_for_block(self, blockhash, timeout=60):
        def test_function():
            return self.last_message.get("block") and self.last_message["block"].block.rehash() == blockhash

        self.wait_until(test_function, timeout=timeout)

    def wait_for_header(self, blockhash, timeout=60):
        def test_function():
            last_headers = self.last_message.get('headers')
            if not last_headers:
                return False
            return last_headers.headers[0].rehash() == int(blockhash, 16)

        self.wait_until(test_function, timeout=timeout)

    def wait_for_merkleblock(self, blockhash, timeout=60):
        def test_function():
            last_filtered_block = self.last_message.get('merkleblock')
            if not last_filtered_block:
                return False
            return last_filtered_block.merkleblock.header.rehash() == int(blockhash, 16)

        self.wait_until(test_function, timeout=timeout)

    def wait_for_getdata(self, hash_list, timeout=60):
        """Waits for a getdata message.

        The object hashes in the inventory vector must match the provided hash_list."""
        def test_function():
            last_data = self.last_message.get("getdata")
            if not last_data:
                return False
            return [x.hash for x in last_data.inv] == hash_list

        self.wait_until(test_function, timeout=timeout)

    def wait_for_getheaders(self, timeout=60):
        """Waits for a getheaders message.

        Receiving any getheaders message will satisfy the predicate. the last_message["getheaders"]
        value must be explicitly cleared before calling this method, or this will return
        immediately with success. TODO: change this method to take a hash value and only
        return true if the correct block header has been requested."""
        def test_function():
            return self.last_message.get("getheaders")

        self.wait_until(test_function, timeout=timeout)

    def wait_for_inv(self, expected_inv, timeout=60):
        """Waits for an INV message and checks that the first inv object in the message was as expected."""
        if len(expected_inv) > 1:
            raise NotImplementedError("wait_for_inv() will only verify the first inv object")

        def test_function():
            return self.last_message.get("inv") and \
                                self.last_message["inv"].inv[0].type == expected_inv[0].type and \
                                self.last_message["inv"].inv[0].hash == expected_inv[0].hash

        self.wait_until(test_function, timeout=timeout)

    def wait_for_handshake(self, timeout=60):
        def test_function():
            return "handshake" in self.last_message

        self.wait_until(test_function, timeout=timeout)

    # Message sending helper functions

    def send_and_ping(self, message, timeout=60):
        self.send_message(message)
        self.sync_with_ping(timeout=timeout)

    def sync_send_with_ping(self, timeout=60):
        """Ensure SendMessages is called on this connection"""
        # Calling sync_with_ping twice requires that the node calls
        # `ProcessMessage` twice, and thus ensures `SendMessages` must have
        # been called at least once
        self.sync_with_ping()
        self.sync_with_ping()

    def sync_with_ping(self, timeout=60):
        """Ensure ProcessMessages is called on this connection"""
        self.send_message({
            "ping_request": {
                    "nonce": self.ping_counter,
                }
            }
        )
        def test_function():
            return self.last_message.get("ping_response") and self.last_message["ping_response"]["nonce"] == self.ping_counter

        self.wait_until(test_function, timeout=timeout)

        self.ping_counter += 1


# One lock for synchronizing all data access between the network event loop (see
# NetworkThread below) and the thread running the test logic.  For simplicity,
# P2PConnection acquires this lock whenever delivering a message to a P2PInterface.
# This lock should be acquired in the thread running the test logic to synchronize
# access to any data shared with the P2PInterface or P2PConnection.
p2p_lock = threading.Lock()


class NetworkThread(threading.Thread):
    network_event_loop = None

    def __init__(self):
        super().__init__(name="NetworkThread")
        # There is only one event loop and no more than one thread must be created
        assert not self.network_event_loop

        NetworkThread.listeners = {}
        NetworkThread.protos = {}
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        NetworkThread.network_event_loop = asyncio.new_event_loop()

    def run(self):
        """Start the network thread."""
        self.network_event_loop.run_forever()

    def close(self, timeout=10):
        """Close the connections and network event loop."""
        self.network_event_loop.call_soon_threadsafe(self.network_event_loop.stop)
        wait_until_helper(lambda: not self.network_event_loop.is_running(), timeout=timeout)
        self.network_event_loop.close()
        self.join(timeout)
        # Safe to remove event loop.
        NetworkThread.network_event_loop = None

    @classmethod
    def listen(cls, p2p, callback, port=None, addr=None, idx=1):
        """ Ensure a listening server is running on the given port, and run the
        protocol specified by `p2p` on the next connection to it. Once ready
        for connections, call `callback`."""

        if port is None:
            assert 0 < idx <= MAX_NODES
            port = p2p_port(MAX_NODES - idx)
        if addr is None:
            addr = '127.0.0.1'

        coroutine = cls.create_listen_server(addr, port, callback, p2p)
        cls.network_event_loop.call_soon_threadsafe(cls.network_event_loop.create_task, coroutine)

    @classmethod
    async def create_listen_server(cls, addr, port, callback, proto):
        def peer_protocol():
            """Returns a function that does the protocol handling for a new
            connection. To allow different connections to have different
            behaviors, the protocol function is first put in the cls.protos
            dict. When the connection is made, the function removes the
            protocol function from that dict, and returns it so the event loop
            can start executing it."""
            response = cls.protos.get((addr, port))
            cls.protos[(addr, port)] = None
            return response

        if (addr, port) not in cls.listeners:
            # When creating a listener on a given (addr, port) we only need to
            # do it once. If we want different behaviors for different
            # connections, we can accomplish this by providing different
            # `proto` functions

            listener = await cls.network_event_loop.create_server(peer_protocol, addr, port)
            logger.debug("Listening server on %s:%d should be started" % (addr, port))
            cls.listeners[(addr, port)] = listener

        cls.protos[(addr, port)] = proto
        callback(addr, port)


class P2PDataStore(P2PInterface):
    """A P2P data store class.

    Keeps a block and transaction store and responds correctly to getdata and getheaders requests."""

    def __init__(self):
        super().__init__()
        # store of blocks. key is block hash, value is a block
        self.block_store = {}
        self.last_block_hash = ''

        # store of txs. key is txid, value is a CTransaction object
        self.tx_store = {}
        self.getdata_requests = []

    def submit_tx(self, tx):
        self._store_txs([tx])
        return self._send_tx_announcement(calc_tx_id(tx))

    def _store_txs(self, txs):
        with p2p_lock:
            for tx in txs:
                self.tx_store[calc_tx_id(tx)] = tx

    def _send_tx_announcement(self, tx_id):
        return self.send_message({ 'new_transaction': "0x" + tx_id })

    def on_transaction_request(self, request):
        tx_id = request['transaction_request'][2:]
        tx = self.tx_store.get(tx_id)

        if tx: response = {'found': tx}
        else: response = {'not_found': tx_id}

        self.send_message({'transaction_response': response})

    def on_header_list_request(self, message):
        """Search back through our block store for the locator, and reply with a headers message if found."""

        if not self.last_block_hash:
            self.send_message({'header_list': []})
            return

        locator = message['header_list_request']

        headers_list = [self.block_store[self.last_block_hash]]
        while calc_block_id(headers_list[-1]) not in locator:
            # Walk back through the block store, adding headers to headers_list
            # as we go.
            prev_block_hash = headers_list[-1]['prev_block_id']
            if prev_block_hash in self.block_store:
                prev_block_header = self.block_store[prev_block_hash]
                headers_list.append(prev_block_header)
            else:
                logger.debug('block hash {} not found in block store'.format(hex(prev_block_hash)))
                break

        # Truncate the list if there are too many headers
        headers_list = headers_list[:-MAX_HEADERS_RESULTS - 1:-1]

        self.send_message({'header_list': ["0x" + hdr_hash for hdr_hash in headers_list]})

    def send_blocks_and_test(self, blocks, node, *, success=True, force_send=False, reject_reason=None, expect_disconnect=False, timeout=60):
        """Send blocks to test node and test whether the tip advances.

         - add all blocks to our block_store
         - send a headers message for the final block
         - the on_getheaders handler will ensure that any getheaders are responded to
         - if force_send is False: wait for getdata for each of the blocks. The on_getdata handler will
           ensure that any getdata messages are responded to. Otherwise send the full block unsolicited.
         - if success is True: assert that the node's tip advances to the most recent block
         - if success is False: assert that the node's tip doesn't advance
         - if reject_reason is set: assert that the correct reject message is logged"""

        assert False, "Not yet ported to Mintlayer"

        with p2p_lock:
            for block in blocks:
                self.block_store[block.sha256] = block
                self.last_block_hash = block.sha256

        reject_reason = [reject_reason] if reject_reason else []
        with node.assert_debug_log(expected_msgs=reject_reason):
            if force_send:
                for b in blocks:
                    self.send_message(msg_block(block=b))
            else:
                self.send_message(msg_headers([CBlockHeader(block) for block in blocks]))
                self.wait_until(
                    lambda: blocks[-1].sha256 in self.getdata_requests,
                    timeout=timeout,
                    check_connected=success,
                )

            if expect_disconnect:
                self.wait_for_disconnect(timeout=timeout)
            else:
                self.sync_with_ping(timeout=timeout)

            if success:
                self.wait_until(lambda: node.getbestblockhash() == blocks[-1].hash, timeout=timeout)
            else:
                assert node.getbestblockhash() != blocks[-1].hash

    def send_txs_and_test(self, txs, node, *, success=True, expect_disconnect=False, reject_reason=None):
        """Send txs to test node and test whether they're accepted to the mempool.

         - add all txs to our tx_store
         - send tx messages for all txs
         - if success is True/False: assert that the txs are/are not accepted to the mempool
         - if expect_disconnect is True: Skip the sync with ping
         - if reject_reason is set: assert that the correct reject message is logged."""

        assert False, "Not yet ported to Mintlayer"

        self._store_txs(txs)

        reject_reason = [reject_reason] if reject_reason else []
        with node.assert_debug_log(expected_msgs=reject_reason):
            for tx in txs:
                self.send_message({ 'new_transaction': "0x" + calc_tx_id(tx) })

            if expect_disconnect:
                self.wait_for_disconnect()
            else:
                self.sync_with_ping()

            raw_mempool = node.getrawmempool()
            if success:
                # Check that all txs are now in the mempool
                for tx in txs:
                    assert tx.hash in raw_mempool, "{} not found in mempool".format(tx.hash)
            else:
                # Check that none of the txs are now in the mempool
                for tx in txs:
                    assert tx.hash not in raw_mempool, "{} tx found in mempool".format(tx.hash)

class P2PTxInvStore(P2PInterface):
    """A P2PInterface which stores a count of how many times each txid has been announced."""
    def __init__(self):
        super().__init__()
        self.tx_invs_received = defaultdict(int)

    def on_inv(self, message):
        super().on_inv(message) # Send getdata in response.
        # Store how many times invs have been received for each tx.
        for i in message.inv:
            if (i.type == MSG_TX) or (i.type == MSG_WTX):
                # save txid
                self.tx_invs_received[i.hash] += 1

    def get_invs(self):
        with p2p_lock:
            return list(self.tx_invs_received.keys())

    def wait_for_broadcast(self, txns, timeout=60):
        """Waits for the txns (list of txids) to complete initial broadcast.
        The mempool should mark unbroadcast=False for these transactions.
        """
        # Wait until invs have been received (and getdatas sent) for each txid.
        self.wait_until(lambda: set(self.tx_invs_received.keys()) == set([int(tx, 16) for tx in txns]), timeout=timeout)
        # Flush messages and wait for the getdatas to be processed
        self.sync_with_ping()
