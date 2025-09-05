import argparse
import os
import pathlib
import requests
import sys
import time
from collections import namedtuple
from urllib.parse import urlparse


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_OUTPUT_FILE = SCRIPT_DIR.joinpath("output", "mainnet_block_timestamps_targets.csv")

ITEMS_PER_REQUEST = 100


BlockInfoFoHeight = namedtuple(
    "BlockInfoFoHeight", ["timestamp", "target"])

class Error(Exception):
    pass


class Handler():
    def __init__(self, args):
        self.api_server_url = args.api_server_url
        self.session = requests.Session()
        self.output_file = pathlib.Path(args.output_file).resolve()

        if len(urlparse(self.api_server_url).scheme) == 0:
            raise Error("The provided URL must contain a scheme")

    def url(self, path):
        return f"{self.api_server_url}/api/v2/{path}"

    def get(self, path, params):
        response = self.session.get(self.url(path), params=params)
        response.raise_for_status()
        return response.json()

    def run(self):
        genesis_info = self.get("chain/genesis", {})

        block_infos_by_height = {}
        starting_height = 1
        last_print_time_ns = time.time_ns()
        while True:
            block_infos = self.get(
                "chain", {"offset": starting_height, "items": ITEMS_PER_REQUEST})

            # Sanity check
            assert(len(block_infos) == 0 or block_infos[0]["block_height"] == starting_height)

            for block_info in block_infos:
                height = block_info["block_height"]
                block_infos_by_height[height] = BlockInfoFoHeight(
                    timestamp=block_info["timestamp"],
                    target=int(block_info["target"], 16)
                )

            starting_height += len(block_infos)
            if len(block_infos) < ITEMS_PER_REQUEST:
                break

            # Print something every second, to cnfirm that the script makes some progress.
            if time.time_ns() - last_print_time_ns >= 1000000000:
                print(f"Retrieved {len(block_infos_by_height)} block infos")
                last_print_time_ns = time.time_ns()

        # Add the genesis (the only reason to add it last is to make the printed
        # "Retrieved x block infos" lines look nicer).
        block_infos_by_height[0] = BlockInfoFoHeight(
            # Note: ["timestamp"]["timestamp"] is not a typo - we indeed return it
            # in this weird way.
            timestamp=genesis_info["timestamp"]["timestamp"],
            # Use a bogus target.
            target=0
        )

        print(f"Writing {len(block_infos_by_height)} block infos to {self.output_file}")
        os.makedirs(self.output_file.parent, exist_ok=True)

        with open(self.output_file, "w") as output:
            prev_height = -1
            for height in sorted(block_infos_by_height.keys()):
                # Sanity check
                if height != prev_height + 1:
                    raise Error(
                        f"Block heights are not consecutive: current height is {height}, prev height is {prev_height}"
                    )
                prev_height = height

                block_info = block_infos_by_height[height]
                output.write(f"{block_info.timestamp}, {block_info.target}\n")


def main():
    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--api-server-url',
                            help='API server URL', required=True)
        parser.add_argument('--output-file',
                            help='Output file', default=DEFAULT_OUTPUT_FILE)
        args = parser.parse_args()

        Handler(args).run()
    except Error as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
