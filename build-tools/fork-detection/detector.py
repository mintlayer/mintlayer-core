import argparse
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Optional
from urllib.parse import urlparse

from utils import (
    colored, dir_missing_or_empty, exhaustive_stream_line_reader, hide_cursor, show_cursor,
    init_logger, pretty_print_banned_peers,
    CONSOLE_PRINTER, LOGGER as log, NODE_OUTPUT_PREFIX_COLOR, NODE_RPC_USER, NODE_RPC_PWD,
    Error, APIServerClient, BannedPeer, EmailSender, NodeRPCClient,
)


DEFAULT_NODE_CMD = "cargo run --release --bin node-daemon --"
DEFAULT_NODE_RPC_BIND_ADDR = "127.0.0.1:12345"
DEFAULT_CHAIN_TYPE = "mainnet"
CHAIN_TYPE_CHOICES = ["mainnet", "testnet"]
CONTINUE_OPTION_NAME = "continue"

CUR_ATTEMPT_SUBDIR = "current_attempt"
SAVED_ATTEMPTS_SUBDIR = "saved_attempts"

FLAGS_SUBDIR = "flags"
NODE_DATA_SUBDIR = "node_data"
SAVED_PEER_DBS_SUBDIR = "saved_peer_dbs"

LATEST_PEER_DB_SUBDIR = "latest"
PREV_PEER_DB_SUBDIR = "previous"

# Note: this is defined by the node and cannot be changed.
PEER_DB_SUBDIR_IN_NODE_DATA = "peerdb-lmdb"

# If the height difference between the current tip and a stale block is bigger than or equal to
# this value, a reorg to the stale block is no longer possible.
MAX_REORG_DEPTH = 1000

# The mapping from node's output to the name of the flag that must be automatically created
# as a result.
NODE_OUTPUT_LINE_REGEX_TO_FLAG_MAPPING = [
    (re.compile(r"\bCRITICAL\b"), "critical_error"),
    (re.compile(r"Checkpoint mismatch"), "checkpoint_mismatch"),
    (re.compile(r"\bERROR\b.+\bprocess_block\b"), "process_block_failure"),
    (re.compile(r"\bERROR\b.+\bpreliminary_block_check\b"), "preliminary_block_check_failure"),
    (re.compile(r"\bERROR\b.+\bpreliminary_headers_check\b"), "preliminary_headers_check_failure"),
]

ENDED_UP_ON_A_FORK_FLAG_NAME = "ended_up_on_a_fork"
NO_INCOMING_BLOCKS_WHILE_ON_STALE_CHAIN_FLAG_NAME = "no_incoming_blocks_while_on_stale_chain"

NODE_OUTPUT_LINE_NEW_TIP_REGEX = re.compile(
    r"NEW TIP in chainstate (?P<block_id>[0-9A-Fa-f]+) with height (?P<height>\d+), timestamp: (?P<timestamp>\d+)"
)

# The regex used to decide whether a node's output line should be printed to the console
# (we want to avoid debug and info lines since they're both too noisy during sync and put extra
# strain on the console app).
# Note that this is not 100% reliable, because a log record can technically span multiple lines,
# only the first of which will contain the severity. But at this moment we don't seem to emit
# multi-line log records during syncing (except for the initial "Starting with the following config").
# But even if we did, this approach is "good enough" anyway, since you can always look into the log
# file for the missing details.
NODE_OUTPUT_LINE_TO_PRINT_REGEX = re.compile(r"^\S+\s+(WARN|ERROR)\b")

# The regex by which we determine that the node is actually being started; this is mainly needed
# because by default we invoke cargo, which may have to do a lengthy compilation first.
# Also note that we use a log line indicating that p2p has already been started (instead of, say,
# an earlier log line such as "Starting mintlayer-core"). This helps catching the situation
# when the node starts and immediately exists due to the p2p port being unavailable.
NODE_STARTUP_OUTPUT_LINE_REGEX = re.compile(r"p2p.*Starting SyncManager")

DEFAULT_BAN_DURATION_HOURS = 12

# Custom disconnection reason to send to peers when banning them. We don't want the default
# "Your address is banned" to be sent, because it sounds like the peer's node is faulty.
# We also don't want to be too specific, e.g. the peer doesn't need to know thar something
# called "fork detector" is running somewhere. So we choose a reason that is somewhat vague.
# Also note that since we ban peers when networking is already disabled, the peer can only
# get this message when attempting an outbound connectiion to the detector's node.
BAN_REASON_STRING = "Cannot accept connections at this moment"

# We use Queue.shutdown which is only available since Python v3.13
MIN_PYTHON_VERSION_MAJOR = 3
MIN_PYTHON_VERSION_MINOR = 13

PERMABANNED_PEERS_FILE = "permabanned_peers.txt"
PERMABAN_DURATION_DAYS = 30
PERMABAN_DURATION_SECS = 3600 * 24 * PERMABAN_DURATION_DAYS

class Handler():
    def __init__(self, args, email_sender):
        CONSOLE_PRINTER.set_status("Initializing")

        self.email_sender = email_sender
        self.working_dir = Path(args.working_dir).resolve()
        os.makedirs(self.working_dir, exist_ok=True)

        init_logger(self.working_dir.joinpath("log.txt"))
        log.info("Initializing")

        self.node_cmd = shlex.split(args.node_cmd)

        self.node_rpc_client = NodeRPCClient(args.node_rpc_bind_address)
        self.api_server_client = APIServerClient(args.api_server_url)

        self.saved_attempts_dir = self.working_dir.joinpath(SAVED_ATTEMPTS_SUBDIR)

        self.saved_peer_dbs_dir = self.working_dir.joinpath(SAVED_PEER_DBS_SUBDIR)
        self.latest_peer_db_dir = self.saved_peer_dbs_dir.joinpath(LATEST_PEER_DB_SUBDIR)
        self.prev_peer_db_dir = self.saved_peer_dbs_dir.joinpath(PREV_PEER_DB_SUBDIR)

        self.permabanned_peers_file = self.working_dir.joinpath(PERMABANNED_PEERS_FILE)

        self.cur_attempt_dir = self.working_dir.joinpath(CUR_ATTEMPT_SUBDIR)
        if os.path.exists(self.cur_attempt_dir) and not args.can_continue:
            raise Error(
                (f"The directory {self.cur_attempt_dir} already exists. "
                 f"Either delete it or pass '--{CONTINUE_OPTION_NAME}' to continue.")
            )

        self.cur_attempt_flags_dir = self.cur_attempt_dir.joinpath(FLAGS_SUBDIR)
        self.cur_attempt_node_data_dir = self.cur_attempt_dir.joinpath(NODE_DATA_SUBDIR)
        self.cur_attempt_logs_file = self.cur_attempt_dir.joinpath("node_log.txt")

        self.unban_all = args.unban_all
        self.ban_duration_secs = args.ban_duration_hours * 3600

        self.node_cmd += [
            "--datadir", self.cur_attempt_node_data_dir,
            args.chain_type,
            "--allow-checkpoints-mismatch",
            "--rpc-bind-address", args.node_rpc_bind_address,
            "--rpc-username", NODE_RPC_USER,
            "--rpc-password", NODE_RPC_PWD,
            "--p2p-custom-disconnection-reason-for-banning", BAN_REASON_STRING
        ]
        log.info(f"Node run command: {self.node_cmd}")

    def run(self):
        try:
            while True:
                self.do_full_sync()
        except KeyboardInterrupt:
            log.info("Exiting due to Ctrl-C")

    def do_full_sync(self):
        actual_tip_height = self.api_server_client.get_tip().height
        log.info(f"Starting a new sync iteration, current chain height is {actual_tip_height}")

        os.makedirs(self.cur_attempt_flags_dir, exist_ok=True)
        os.makedirs(self.cur_attempt_node_data_dir, exist_ok=True)

        self.restore_peer_db()

        node_proc_env = os.environ.copy()
        # Note: "chainstate_verbose_block_ids=debug" forces certain block-processing functions
        # in chainstate to print full block ids. We avoid using the "normal" debug log, because
        # it's too noisy, e.g. even "info,chainstate=debug" produces hundreds of megabytes of
        # logs during the full sync.
        node_proc_env["RUST_LOG"] = "info,chainstate_verbose_block_ids=debug"

        node_proc = subprocess.Popen(
            self.node_cmd,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=node_proc_env)

        last_tip_arrival_time = None
        last_tip_height = None

        # Lines from node's console output will be put into this queue.
        node_proc_stdout_queue = Queue()
        Thread(
            target=exhaustive_stream_line_reader,
            args=(node_proc.stdout, node_proc_stdout_queue, self.cur_attempt_logs_file)
        ).start()

        # This is called for each node's output line and on a timeout when reading the line
        # from a queue (in which case the passed line will be None).
        # Returns True if the current attempt should continue and False otherwise.
        def on_node_output_line_or_timeout(line: Optional[str]) -> bool:
            nonlocal actual_tip_height, last_tip_arrival_time, last_tip_height

            line = line if line is not None else ""

            for line_re, flag in NODE_OUTPUT_LINE_REGEX_TO_FLAG_MAPPING:
                if line_re.search(line) is not None:
                    self.touch_flag(flag)

            cur_seconds_since_epoch = time.time()

            if (new_tip_match := NODE_OUTPUT_LINE_NEW_TIP_REGEX.search(line)) is not None:
                block_id = new_tip_match.group("block_id")
                height = int(new_tip_match.group("height"))
                timestamp = int(new_tip_match.group("timestamp"))

                last_tip_arrival_time = cur_seconds_since_epoch
                last_tip_height = height

                if height % 10 == 0:
                    CONSOLE_PRINTER.set_status(f"Synced to height {height}")

                # Update actual_tip_height if we've reached it.
                if height >= actual_tip_height:
                    actual_tip_height = self.api_server_client.get_tip().height

                fresh_block_reached = timestamp >= cur_seconds_since_epoch - 120
                actual_tip_height_reached = height >= actual_tip_height

                # Note: we can't query the API server on every block, because it's a costly operation
                # (unless the API server is being run on the same machine). So we only query it every
                # few hundred blocks or if we're near the end of the sync.
                # Also note:
                # 1) this serves as an additional checkpointing mechanism; it is redundant while
                # the block height is at or below the last checkpoint, but is useful after that
                # point.
                # 2) 500 was chosen because it's also the distance between our checkpoints,
                # but the precise value is not essential.
                if height % 500 == 0 or fresh_block_reached or actual_tip_height_reached:
                    actual_block_id = self.api_server_client.get_block_id(height)
                    if block_id.lower() != actual_block_id.lower():
                        if actual_tip_height - height >= MAX_REORG_DEPTH:
                            self.touch_flag(ENDED_UP_ON_A_FORK_FLAG_NAME)

                        if fresh_block_reached:
                            log.info(f"Fresh block on a stale chain reached (height = {height})")
                            return False

                if actual_tip_height_reached:
                    # Note: the API server may lag behind our node; but it'd be strange if it lagged
                    # by more than 1 block, so we use log.warning in this case.
                    log_func = log.info if height <= actual_tip_height + 1 else log.warning
                    extra = (
                        "" if height == actual_tip_height
                        else f" (the API server is {height-actual_tip_height} block(s) behind)"
                    )
                    log_func(f"Tip reached, height = {height}{extra}")
                    return False
            else:
                seconds_since_last_tip = (
                    cur_seconds_since_epoch - last_tip_arrival_time
                    if last_tip_arrival_time is not None else 0
                )

                # Note: the reason for not receiving any blocks may be that we've already banned
                # all or most of the potential peers. But if we're on a stale chain, then we may
                # not receive any more blocks, so we have to stop.
                # We'll also stop if some flags have already been created.

                if seconds_since_last_tip >= 120:
                    chainstate_info = self.node_rpc_client.get_chainstate_info()
                    tip_id = chainstate_info.best_block_id
                    tip_height = chainstate_info.best_block_height

                    if tip_height != 0:
                        actual_block_id = self.api_server_client.get_block_id(tip_height)

                        if tip_id.lower() != actual_block_id.lower():
                            self.touch_flag(NO_INCOMING_BLOCKS_WHILE_ON_STALE_CHAIN_FLAG_NAME)
                            return False

                    if self.have_flags():
                        log.info("Exiting because we haven't received any blocks in a while, but some flags already exist")
                        return False

            return True

        # This function will be called once the first non-empty line has been received from the node's output.
        def on_node_started():
            # Here we:
            # 1) ensure node RPC is up;
            # 2) ban all peers designated for perma-banning;
            # 3) unban all non-perma-banned peers if self.unban_all is True (this is only done once);

            self.node_rpc_client.ensure_rpc_started()

            permabanned_peers = self.load_permabanned_peers()
            log.debug(f"Banning the following addresses for {PERMABAN_DURATION_DAYS} days: {permabanned_peers}")

            for addr in permabanned_peers:
                self.node_rpc_client.ban_peer(addr, PERMABAN_DURATION_SECS)

            def filter_out_permabanned_peers(peer_list: list[BannedPeer]) -> list[BannedPeer]:
                return [peer for peer in peer_list if peer.ip not in permabanned_peers]

            banned_peers = self.node_rpc_client.get_banned_peers()
            banned_peers_str = pretty_print_banned_peers(banned_peers)

            log.debug(f"Currently banned peers: {banned_peers_str}")

            if self.unban_all:
                self.unban_all = False
                peers_to_unban = filter_out_permabanned_peers(banned_peers)
                if len(peers_to_unban) > 0:
                    log.info("Unbanning currently (non-permanently) banned peers due to the command line option")

                    for peer in peers_to_unban:
                        self.node_rpc_client.unban_peer(peer.ip)

                    banned_peers_after_unban = self.node_rpc_client.get_banned_peers()
                    unexpected_banned_peers = filter_out_permabanned_peers(banned_peers_after_unban)

                    if len(unexpected_banned_peers) > 0:
                        unexpected_banned_peers_str = pretty_print_banned_peers(unexpected_banned_peers)
                        log.warning(f"Some peers are still banned after unban: {unexpected_banned_peers_str}")

        def on_attempt_completion():
            # When a syncing attempt has been finished, but before the node has been stopped,
            # we ban some of the currently connected peers for a long-enough duration:
            # a) so that the next attempt can use different peers;
            # b) to reduce the strain on the network.

            peer_ips_to_ban = self.get_node_peer_ip_addrs_to_ban()

            # Before banning, disable networking; this will disconnect all peers and prevent them
            # from reconnecting again.
            self.node_rpc_client.enable_networking(False)
            # Give the node some time to actually disconnect all peers.
            time.sleep(2)

            for ip_addr in peer_ips_to_ban:
                log.debug(f"Banning {ip_addr}")
                self.node_rpc_client.ban_peer(ip_addr, self.ban_duration_secs)

        try:
            node_started = False
            set_status_and_debug_log("Waiting for the node to start")

            while True:
                # Try getting a line from the queue, catching a potential queue shutdown exception.
                try:
                    # Get a line from the queue, with a timeout.
                    # Call on_node_output_line_or_timeout passing it the line or None if timeout
                    # occurred.
                    try:
                        line = node_proc_stdout_queue.get(timeout=10)

                        if NODE_OUTPUT_LINE_TO_PRINT_REGEX.search(line) is not None:
                            stdout_prefix = colored("node> ", NODE_OUTPUT_PREFIX_COLOR)
                            CONSOLE_PRINTER.print_to_stderr(f"{stdout_prefix} {line}", end="")

                        if not node_started and NODE_STARTUP_OUTPUT_LINE_REGEX.search(line) is not None:
                            node_started = True
                            set_status_and_debug_log("Node started")
                            on_node_started()
                    except queue.Empty:
                        line = None

                    if not on_node_output_line_or_timeout(line):
                        break
                except queue.ShutDown:
                    # This means that the node has exited prematurely. But we check for this
                    # via the "poll" call below, so here it can be ignored.
                    pass

                exit_code = node_proc.poll()
                if exit_code is not None:
                    raise Error(f"The node exited prematurely with exit code {exit_code}")

            # Shutdown the queue to prevent the reading thread from putting moree lines to it.
            node_proc_stdout_queue.shutdown()

            on_attempt_completion()

        finally:
            if last_tip_height is not None:
                log.debug(f"Last handled tip height: {last_tip_height}")

            set_status_and_debug_log("Terminating the node")

            # Note: for some reason the node doesn't want to terminate sometimes,
            # in particular this may happen when hitting Ctrl-C. Though the Ctrl-C case
            # is not particularly important (since you can always hit it again), we want
            # to protect against this situation during the normal script execution.
            # So, we try terminating the node a few times and if it doesn't react, we kill it.
            for i in range(3):
                node_proc.terminate()
                try:
                    node_proc.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    log.warning(f"Node didn't terminate, attempt {i}")
                    pass
            else:
                log.warning("Killing the node")
                node_proc.kill()
                node_proc.wait()

        self.save_peer_db()

        # If the script has created some flags, save the directory
        if self.have_flags():
            os.makedirs(self.saved_attempts_dir, exist_ok=True)

            backup_dir_name = datetime.today().strftime("%Y-%m-%d_%H-%M-%S")
            backup_dir = self.saved_attempts_dir.joinpath(backup_dir_name)

            warning_msg = ("Sync iteration ended with some issues, "
                           f"backing up the the attempt's dir to {backup_dir}")
            log.warning(warning_msg)
            self.email_sender.send("Warning", warning_msg)

            os.rename(self.cur_attempt_dir, backup_dir)
        else:
            log.info("Sync iteration ended without issues, removing the attempt's dir")
            shutil.rmtree(self.cur_attempt_dir)

    def have_flags(self):
        return len(os.listdir(self.cur_attempt_flags_dir)) > 0

    # Return the list of ip addresses we want to ban and the end of a sync attempt,
    # to prevent syncing with the same peers again and again.
    def get_node_peer_ip_addrs_to_ban(self):
        peers = self.node_rpc_client.get_connected_peers()

        # Note: non-null 'last_tip_block_time' means that the peer has sent us a block that
        # became our tip. Other peers that had the same block but sent it a bit later are not
        # counted, which means that it's technically possible to have a gadzillion peers where
        # only one of them has a non-null 'last_tip_block_time'. In practice though most of the
        # currently connected peers should have a non-null 'last_tip_block_time' after a full sync.
        peers_with_last_tip_block_time = [
            peer for peer in peers if peer["last_tip_block_time"] is not None
        ]

        log.debug(f"Obtaining peer ips to ban; total connected peers: {len(peers)}, "
                  f"peers with 'last_tip_block_time': {len(peers_with_last_tip_block_time)}")

        # Note: the return addresses have the form '{ip_addr}:{port}', which is interpreted
        # as path by urlparse; prepending "//" convinces it that it's a full address.
        return [urlparse("//" + peer["address"]).hostname for peer in peers_with_last_tip_block_time]

    # After the current attempt has been completed, save the current peer db.
    def save_peer_db(self):
        os.makedirs(self.saved_peer_dbs_dir, exist_ok=True)

        if os.path.exists(self.prev_peer_db_dir):
            shutil.rmtree(self.prev_peer_db_dir)

        if os.path.exists(self.latest_peer_db_dir):
            os.rename(self.latest_peer_db_dir, self.prev_peer_db_dir)

        cur_peer_db_dir = self.cur_attempt_node_data_dir.joinpath(PEER_DB_SUBDIR_IN_NODE_DATA)
        shutil.copytree(cur_peer_db_dir, self.latest_peer_db_dir)

    # Before starting the next attempt, if the node dir is missing a peer db, copy the saved
    # peer db into it.
    def restore_peer_db(self):
        cur_peer_db_dir = self.cur_attempt_node_data_dir.joinpath(PEER_DB_SUBDIR_IN_NODE_DATA)

        if dir_missing_or_empty(cur_peer_db_dir) and os.path.exists(self.latest_peer_db_dir):
            shutil.copytree(self.latest_peer_db_dir, cur_peer_db_dir, dirs_exist_ok=True)

    # Touch a flag optionally appending some contents to it
    def touch_flag(self, flag: str, contents=None):
        flag_file = self.cur_attempt_flags_dir.joinpath(flag)
        with open(flag_file, 'a') as file:
            if contents is not None:
                file.write(contents)
                file.write("\n")

        log.warning(f"Flag created: {flag}")

    def load_permabanned_peers(self) -> set[str]:
        def trim_line(line):
            # Allow the file to have comments
            return line.split("#", 1)[0].strip()

        log.debug(f"Checking {self.permabanned_peers_file} for the list of permabanned peer addresses")

        try:
            with open(self.permabanned_peers_file, "r") as file:
                lines = file.readlines()
                lines = [
                    trimmed_line for line in lines
                    if len(trimmed_line := trim_line(line)) > 0
                ]
                return set(lines)
        except FileNotFoundError:
            return set()


def set_status_and_debug_log(status):
    log.debug(status)
    CONSOLE_PRINTER.set_status(status)


def main():
    if sys.version_info < (MIN_PYTHON_VERSION_MAJOR, MIN_PYTHON_VERSION_MINOR):
        print(f"This script requires Python {MIN_PYTHON_VERSION_MAJOR}.{MIN_PYTHON_VERSION_MINOR} or higher")
        sys.exit(1)

    hide_cursor()

    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument(
            "--node-cmd",
            help="Command to run the node",
            default=DEFAULT_NODE_CMD)
        parser.add_argument(
            "--node-rpc-bind-address",
            help="Node PRC bind address",
            default=DEFAULT_NODE_RPC_BIND_ADDR)
        parser.add_argument(
            "--api-server-url",
            help='API server URL', required=True)
        parser.add_argument(
            "--chain-type",
            help="Chain type",
            choices=CHAIN_TYPE_CHOICES,
            default=DEFAULT_CHAIN_TYPE)
        parser.add_argument(
            "--working-dir",
            help="Working directory, where all the output will be put",
            required=True)
        parser.add_argument(
            f"--{CONTINUE_OPTION_NAME}",
            help=(f"Proceed even if the '{CUR_ATTEMPT_SUBDIR}' subdirectory "
                   "already exists in the working dir"),
            action="store_true",
            dest="can_continue")
        parser.add_argument(
            "--ban-duration",
            help="Ban duration, in hours",
            dest="ban_duration_hours",
            default=DEFAULT_BAN_DURATION_HOURS)
        parser.add_argument(
            "--unban-all",
            help="Unban all node's peers on start",
            action="store_true")
        parser.add_argument(
            "--notification-email",
            help="Send notifications to this email using the local SMTP server",
            default=None)
        parser.add_argument(
            "--notification-email-from",
            help=("The from address for the notification email. "
                  "If None, the --notification-email value will be used"),
            default=None)
        args = parser.parse_args()

        email_sender = EmailSender(
            args.chain_type, args.notification_email, args.notification_email_from
        )

        try:
            Handler(args, email_sender).run()
        except Exception as e:
            email_sender.send("Error", f"Script terminated due to exception: {e}")
            raise
    except Error as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        CONSOLE_PRINTER.set_status("")
        show_cursor()


if __name__ == "__main__":
    main()
