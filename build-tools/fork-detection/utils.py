import json
import logging
import os
import platform
import queue
import requests
import smtplib
import sys
import time
from collections import namedtuple
from email.mime.text import MIMEText
from pathlib import Path
from queue import Queue
from threading import Lock
from typing import TextIO
from urllib.parse import urlparse

import termcolor # type: ignore


class Error(Exception):
    pass


# 'color' can be either the name of the color, e.g. "red", or a tuple where the first element
# is the name of the color and the second one the attributes, e.g. ("red", ["dark", "bold"]),
# or simply None.
def colored(text, color):
    if color is None:
        return text
    elif isinstance(color, tuple):
        return termcolor.colored(text, color[0], attrs=color[1])
    else:
        return termcolor.colored(text, color)


# Color constants suitable for passing to the "colored" function.
# Note we are using the color names from termcolor v1.x, which doesn't have the "light_" colors.
# The "bold" attribute makes the color brighter, "dark" farker and "dark bold" is between
# "dark" and "bold".
# Note: the colors were chosen when using a Linux terminal with a dark theme, though they
# look ok with a light theme too.
STATUS_COLOR = ("cyan", ["bold"])
LOG_DEBUG_COLOR = ("white", ["bold", "dark"])
# "None" means it will be the normal foreground color, i.e. white for a dark theme and
# black for a light one.
LOG_INFO_COLOR = None
LOG_WARN_COLOR = "yellow"
LOG_ERROR_COLOR = "red"
LOG_CRITICAL_COLOR = ("red", ["bold"])
NODE_OUTPUT_PREFIX_COLOR = "green"

NODE_RPC_USER = "user"
NODE_RPC_PWD = "pwd"

API_SERVER_TIMEOUT_SECS = 180
NODE_RPC_TIMEOUT_SECS = 180

LOGGER = logging.getLogger("detector_logger")


# This class maintains a "status line" at the bottom of the terminal output, erasing and
# redrawing it when the normal output is performed.
# The status line is written to stdout while the normal output is always printed to stderr.
# Note that all printing in the app has to be done through the same object of this class
# (CONSOLE_PRINTER defined below), otherwise the output will be broken.
class ConsolePrinterWithStatus:
    def __init__(self):
        self.status = ""
        self.mutex = Lock()

        if sys.stdout.isatty():
            # Prepare the line where the status will be shown.
            sys.stdout.write("\n")

    def print_to_stderr(self, line, end = "\n"):
        with self.mutex:
            # If both are the same terminal, need to erase the status, print the line
            # and then print the status again.
            if stdout_and_stderr_are_same_terminal():
                # Note: technically we could write the line and then the required number
                # of extra spaces, but that number is non-trivial to determine if the line
                # or the status contain control chars.
                self._erase_status()
                sys.stdout.write(line)
                sys.stdout.write(end)
                sys.stdout.write(self.status)
                sys.stdout.flush()
            else:
                print(line, file=sys.stderr)

    def set_status(self, status):
        with self.mutex:
            if sys.stdout.isatty():
                status = colored(status, STATUS_COLOR)
                self._erase_status()
                sys.stdout.write(status)
            else:
                sys.stdout.write(status)
                sys.stdout.write("\n")

            sys.stdout.flush()
            self.status = status

    def _erase_status(self):
        sys.stdout.write("\r")
        sys.stdout.write(" " * len(self.status))
        sys.stdout.write("\r")


CONSOLE_PRINTER = ConsolePrinterWithStatus()


# Log handler that prints the records via CONSOLE_PRINTER.
class LogConsoleHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            CONSOLE_PRINTER.print_to_stderr(msg)
        except Exception:
            self.handleError(record)


# Log formatter that produces colored output.
class LogColoredFormatter(logging.Formatter):
    def __init__(self, fmt: str):
        super().__init__()

        self.formatters = {
            logging.DEBUG: logging.Formatter(colored(fmt, LOG_DEBUG_COLOR)),
            logging.INFO: logging.Formatter(colored(fmt, LOG_INFO_COLOR)),
            logging.WARNING: logging.Formatter(colored(fmt, LOG_WARN_COLOR)),
            logging.ERROR: logging.Formatter(colored(fmt, LOG_ERROR_COLOR)),
            logging.CRITICAL: logging.Formatter(colored(fmt, LOG_CRITICAL_COLOR)),
        }

    def format(self, record):
        formatter = self.formatters.get(record.levelno)
        return formatter.format(record)


def stdout_and_stderr_are_same_terminal():
    if not (sys.stdout.isatty() and sys.stderr.isatty()):
        # At least one of them is not a terminal
        return False

    if sys.platform.startswith("win"):
        # On Windows, if both are terminals, then they should be the same terminal.
        return True

    # On *nix, the more reliable way is to compare ttyname's.
    stdout_name = os.ttyname(sys.stdout.fileno())
    stderr_name = os.ttyname(sys.stderr.fileno())
    return stdout_name == stderr_name


def init_logger(log_file: Path):
    global LOGGER

    fmt = "%(asctime)s - %(levelname)s - %(message)s"

    console_handler = LogConsoleHandler()
    console_handler.setFormatter(LogColoredFormatter(fmt))

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(fmt))

    LOGGER.addHandler(console_handler)
    LOGGER.addHandler(file_handler)

    LOGGER.setLevel(logging.DEBUG)

    # Without this the records will be propagated to the root logger and printed twice.
    LOGGER.propagate = False


def dir_missing_or_empty(path: Path):
    return not os.path.exists(path) or len(os.listdir(path)) == 0


def prettify_duration(duration_secs: int) -> str:
    if duration_secs == 0:
        return "0s"

    result = ""
    def append(val, symbol):
        nonlocal result
        if val != 0:
            sep = " " if len(result) > 0 else ""
            result += f"{sep}{val}{symbol}"

    duration_mins = duration_secs // 60
    duration_hrs = duration_mins // 60
    duration_days = duration_hrs // 24

    append(duration_days, "d")
    append(duration_hrs % 24, "h")
    append(duration_mins % 60, "m")
    append(duration_secs % 60, "s")

    return result


# The function reads lines from the stream and puts them to the queue.
# Even if the queue has been shut down on the receiving end, the function will continue
# to read from the stream until it is closed.
#
# This is intended to be used with subprocess.Popen when its stdout/stderr are in the PIPE mode,
# (because not reading the pipes may result in the child process dead-locking when the pipe
# buffer becomes full).
#
# The function will also log (append) the read lines to the specified file, if provided.
def exhaustive_stream_line_reader(stream: TextIO, queue_obj: Queue, log_file: Path | None = None):
    def reader(log_stream):
        queue_already_shut_down = False

        # Loop until readline returns '', which means that the other end of the stream has been closed.
        for line in iter(stream.readline, ''):
            if log_stream is not None:
                log_stream.write(line)
                log_stream.flush()

            if not queue_already_shut_down:
                try:
                    queue_obj.put(line)
                except queue.ShutDown:
                    queue_already_shut_down = True

        queue_obj.shutdown()

    if log_file is not None:
        with open(log_file, 'a') as log_stream:
            reader(log_stream)
    else:
        reader(None)


BlockInfo = namedtuple("BlockInfo", ["id", "height"])
BannedPeer = namedtuple("BannedPeer", ["ip", "banned_until_as_secs_since_epoch"])
ChainstateInfo = namedtuple("ChainstateInfo", ["best_block_height", "best_block_id", "best_block_timestamp"])


class APIServerClient:
    def __init__(self, server_url):
        if len(urlparse(server_url).scheme) == 0:
            raise Error("The provided API server URL must contain a scheme")

        self.server_url = server_url
        self.session = requests.Session()

    def _get(self, path: str, request_params):
        url = f"{self.server_url}/api/v2/{path}"
        try:
            response = self.session.get(url, params=request_params, timeout=API_SERVER_TIMEOUT_SECS)
        except requests.exceptions.Timeout:
            raise Error(f"API server request to '{path}' timed out")
        except requests.exceptions.ConnectionError:
            raise Error("Cannot connect to the API server")

        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def get_tip(self):
        tip_info = self._get("chain/tip", {})
        return BlockInfo(id=tip_info["block_id"], height=tip_info["block_height"])

    def get_block_id(self, height: int):
        return self._get(f"chain/{height}", {})


class NodeRPCClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.session = requests.Session()

    def _post(self, method: str, method_params, timeout=NODE_RPC_TIMEOUT_SECS, handle_exceptions=True):
        headers = {"Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": method_params,
            "id": 1,
        }
        url = f"http://{NODE_RPC_USER}:{NODE_RPC_PWD}@{self.server_url}"
        try:
            response = self.session.post(url, headers=headers, data=json.dumps(payload), timeout=timeout)
        except requests.exceptions.Timeout:
            if handle_exceptions:
                raise Error(f"Node RPC request '{method}' timed out")
            else:
                raise
        except requests.exceptions.ConnectionError:
            if handle_exceptions:
                raise Error("Cannot connect to the node via RPC")
            else:
                raise

        response.raise_for_status()
        json_data = response.json()

        if "error" in json_data:
            err_code = json_data["error"]["code"]
            err_msg = json_data["error"]["message"]
            raise Error(
                f"Node RPC method '{method}' failed with code {err_code} and message '{err_msg}'"
            )

        return json_data["result"]

    def enable_networking(self, enable: bool):
        self._post("p2p_enable_networking", [enable])

    def get_connected_peers(self):
        return self._post("p2p_get_connected_peers", [])

    def get_banned_peers(self) -> list[BannedPeer]:
        raw_peers = self._post("p2p_list_banned", [])
        pretty_peers = []
        for peer in raw_peers:
            ip = peer[0]
            banned_until_secs = peer[1]["time"]["secs"]
            # Note: we ignore the "nanos" part of the returned duration.
            pretty_peers += [BannedPeer(ip=ip, banned_until_as_secs_since_epoch=banned_until_secs)]

        return pretty_peers

    def ban_peer(self, peer_addr: str, duration_secs: int):
        self._post("p2p_ban", [peer_addr, {"secs":duration_secs, "nanos":0}])

    def unban_peer(self, peer_addr: str):
        self._post("p2p_unban", [peer_addr])

    def get_chainstate_info(self) -> ChainstateInfo:
        info = self._post("chainstate_info", [])
        bb_height = int(info["best_block_height"])
        bb_timestamp = int(info["best_block_timestamp"]["timestamp"])
        bb_id = info["best_block_id"]

        return ChainstateInfo(
            best_block_height=bb_height, best_block_id=bb_id, best_block_timestamp=bb_timestamp
        )

    # Assuming that the node has already been started, wait until it is reachable via rpc.
    def ensure_rpc_started(self):
        max_attempts = 10
        for i in range(max_attempts):
            try:
                # Note: since we're repeating this multiple times, the timeout has to be small.
                self._post("p2p_get_peer_count", [], timeout=5, handle_exceptions=False)
                return
            except requests.exceptions.ConnectionError:
                time.sleep(1)
            except requests.exceptions.Timeout:
                # Try again on timeout too, just don't waste extra time on sleeping.
                pass
        else:
            raise Error("The node is expected to have been started already, but RPC requests don't work")


def pretty_print_banned_peers(banned_peers: list[BannedPeer], multiline = True) -> str:
    cur_secs_since_epoch = int(time.time())

    # Note: the ban time can be in the past if we're restarting the script after a delay.
    # Such peers are not really banned anymore.
    banned_peers = [
        peer for peer in banned_peers if peer.banned_until_as_secs_since_epoch > cur_secs_since_epoch
    ]

    if len(banned_peers) == 0:
        return "[]"

    if multiline:
        result = "[\n"
    else:
        result = "["

    for idx, peer in enumerate(banned_peers):
        duration = prettify_duration(peer.banned_until_as_secs_since_epoch - cur_secs_since_epoch)
        line = f"(ip: {peer.ip}, remaining duration: {duration})"

        if multiline:
            opt_sep = "," if idx != len(banned_peers) - 1 else ""
            result += f"    {line}{opt_sep}\n"
        else:
            opt_sep = ", " if idx != len(banned_peers) - 1 else ""
            result += f"{line}{opt_sep}"

    result += "]"

    return result


def hide_cursor():
    esc_seq = "\033[?25l"
    if sys.stdout.isatty():
        sys.stdout.write(esc_seq)
    if sys.stderr.isatty():
        sys.stderr.write(esc_seq)


def show_cursor():
    esc_seq = "\033[?25h"
    if sys.stdout.isatty():
        sys.stdout.write(esc_seq)
    if sys.stderr.isatty():
        sys.stderr.write(esc_seq)


# Sends notification emails to the specified address if it's not None, otherwise does nothing.
class EmailSender:
    # to_addr - the address to send emails to; if None, nothing will be sent.
    # from_addr - the 'from' address for the emails; if None, to_addr will be used.
    def __init__(self, chain_type: str, to_addr: str | None, from_addr: str | None):
        self.chain_type = chain_type
        self.to_addr = to_addr
        self.from_addr = from_addr or to_addr

    def send(self, msg_subj, msg_body):
        if self.to_addr is not None:
            msg = MIMEText(msg_body)
            msg["Subject"] = msg_subj
            msg["From"] = f"Fork detection script at {platform.node()} ({self.chain_type}) <{self.from_addr}>"
            msg["To"] = self.to_addr

            s = smtplib.SMTP('localhost')
            s.sendmail(self.from_addr, [self.to_addr], msg.as_string())
            s.quit()
