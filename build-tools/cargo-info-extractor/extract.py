#!/usr/bin/env python3
'''
A simple program that extracts certain info from Cargo.toml and prints it to stdout.
To be used in CI.
'''

import argparse
import pathlib
import tomllib


ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
ROOT_CARGO_TOML = ROOT_DIR.joinpath("Cargo.toml")


def get_rust_version(workspace_settings):
    version = workspace_settings["package"]["rust-version"]

    if len(version.split('.')) == 2:
        version = version + '.0'

    return version


def get_trezor_repo_rev(workspace_settings):
    return workspace_settings["dependencies"]["trezor-client"]["rev"]


def main():
    parser = argparse.ArgumentParser()
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument('--rust-version', action='store_true', help='extract Rust version')
    mutex_group.add_argument('--trezor-repo-rev', action='store_true', help='extract Trezor repo revision')
    args = parser.parse_args()

    with open(ROOT_CARGO_TOML, "rb") as file:
        cargo_toml_root = tomllib.load(file)

    workspace_settings = cargo_toml_root["workspace"]

    if args.rust_version:
        result = get_rust_version(workspace_settings)
        print(result)
    elif args.trezor_repo_rev:
        result = get_trezor_repo_rev(workspace_settings)
        print(result)


if __name__ == "__main__":
    main()
