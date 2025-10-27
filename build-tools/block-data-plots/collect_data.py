import argparse
import subprocess
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR.joinpath("output")
DEFAULT_OUTPUT_FILE_NAME_FMT = "{chain_type}_block_timestamps_targets.csv"
ROOT_DIR = SCRIPT_DIR.parent.parent

DEFAULT_CHAIN_TYPE = "mainnet"
CHAIN_TYPE_CHOICES = ["mainnet", "testnet"]


def collect_data(args):
    if args.output_file is None:
        output_file = DEFAULT_OUTPUT_DIR.joinpath(
            DEFAULT_OUTPUT_FILE_NAME_FMT.format(chain_type=args.chain_type)
        )
    else:
        output_file = args.output_file

    cmd = [
        "cargo", "run", "--release", "--bin", "chainstate-db-dumper", "--",
        "--chain-type", args.chain_type,
        "--output-file", output_file,
        "--mainchain-only=true",
        "--fields=height,timestamp,target",
        "--from_height=0"
    ]

    if args.node_data_dir is not None:
        cmd += ["--db-dir", Path(args.node_data_dir).joinpath("chainstate-lmdb")]

    print(f"Using command {cmd}")

    subprocess.check_call(cmd, cwd=ROOT_DIR)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--chain-type",
        help="Chain type",
        choices=CHAIN_TYPE_CHOICES,
        default=DEFAULT_CHAIN_TYPE)
    parser.add_argument("--node-data-dir",
        help="Node data directory; the default value is the default data directory "
             "corresponding to the specified chain type",
        default=argparse.SUPPRESS)
    parser.add_argument("--output-file",
        help=f"Output file path; by default, the file will be put to '{DEFAULT_OUTPUT_DIR}' "
             f"under the name '{DEFAULT_OUTPUT_FILE_NAME_FMT}'",
        default=argparse.SUPPRESS)

    args = parser.parse_args()

    # Note: the above "default=argparse.SUPPRESS" suppresses showing the ugly "default: None"
    # in the argument's help, but because of it the attribute won't be present if omitted.
    args.node_data_dir = getattr(args, "node_data_dir", None)
    args.output_file = getattr(args, "output_file", None)

    collect_data(args)


if __name__ == "__main__":
    main()
