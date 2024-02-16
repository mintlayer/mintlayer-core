#!/usr/bin/env python3
'''
A simple program that extracts the rust version and prints it to stdout.
To be used in CI.
'''

import os
import re
import sys
import toml
import itertools

def get_rust_version():
    cargo_toml_root = toml.load('Cargo.toml')

    if "workspace" not in cargo_toml_root:
        raise KeyError("'workspace' not found in root. Is this the root Cargo.toml file?")
    workspace_settings = cargo_toml_root["workspace"]

    if "package" not in workspace_settings:
        raise KeyError("'package' not found in 'workspace' in [package]")
    package_settings = workspace_settings["package"]

    if "rust-version" not in package_settings:
        raise KeyError("Rust version is not specified in [workspace]")

    version = package_settings["rust-version"]

    # Unfortunately, rust-init doesn't support completing the version on its own, so we just pad with whatever works
    if len(version.split('.')) == 2:
        version = version + '.0'

    return version

if __name__ == "__main__":
    rust_version = get_rust_version()
    print(rust_version)
