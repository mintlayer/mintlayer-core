#!/usr/bin/env python3
# Some simple custom code lints, mostly implemented by means of grepping code

import os
import re
import sys
import toml
import itertools
import fnmatch

SCALECODEC_RE = r'\bparity_scale_codec(_derive)?::'
JSONRPSEE_RE = r'\bjsonrpsee[_a-z0-9]*::'

LICENSE_TEMPLATE = [
    r'// Copyright \(c\) 202[0-9](-202[0-9])? .+',
    r'// opensource@mintlayer\.org',
    r'// SPDX-License-Identifier: MIT',
    r'// Licensed under the MIT License;',
    r'// you may not use this file except in compliance with the License\.',
    r'// You may obtain a copy of the License at',
    r'//',
    r'// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE',
    r'//',
    r'// Unless required by applicable law or agreed to in writing, software',
    r'// distributed under the License is distributed on an "AS IS" BASIS,',
    r'// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.',
    r'// See the License for the specific language governing permissions and',
    r'// limitations under the License\.',
    r'|//'
]

COMMON_EXCLUDE_DIRS = [
    'target',
    '.git',
    'build-tools/docker/example-mainnet/mintlayer-data',
    'build-tools/docker/example-mainnet-dns-server/mintlayer-data',
    'wasm-wrappers/pkg',
    'wasm-wrappers/js-bindings-test/dist',
]


# List Rust source files
def rs_sources(exclude = []):
    return sources_with_extensions(['.rs'], exclude)


# List Cargo config files
def cargo_config_files(exclude = []):
    return sources_with_extensions(['.toml'], exclude)


# List Python source files
def py_sources(exclude = []):
    return sources_with_extensions(['.py'], exclude)


# Cargo.toml files
def cargo_toml_files(exclude = []):
    exclude = [ os.path.normpath(dir) for dir in COMMON_EXCLUDE_DIRS + ['.github'] + exclude ]
    is_excluded = lambda top, d: os.path.normpath(os.path.join(top, d).lower()) in exclude

    for top, dirs, files in os.walk('.', topdown=True):
        dirs[:] = [ d for d in dirs if not is_excluded(top, d) ]
        for file in files:
            if file == 'Cargo.toml':
                yield os.path.join(top, file)

def _sources_with_extension(ext: str, exclude = []):
    exclude = [ os.path.normpath(dir) for dir in COMMON_EXCLUDE_DIRS + ['.github'] + exclude ]
    is_excluded = lambda top, d: os.path.normpath(os.path.join(top, d).lower()) in exclude

    for top, dirs, files in os.walk('.', topdown=True):
        dirs[:] = [ d for d in dirs if not is_excluded(top, d) ]
        for file in files:
            if os.path.splitext(file)[1].lower() == ext:
                yield os.path.join(top, file)

# List source files with given extensions
def sources_with_extensions(exts: list[str], exclude = []):
    return list(itertools.chain(*[_sources_with_extension(ext, exclude) for ext in exts]))


# All files
def all_files(exclude = []):
    exclude_full_paths = [ os.path.normpath(dir) for dir in COMMON_EXCLUDE_DIRS + exclude ]
    exclude_dir_names = ['__pycache__']

    def is_excluded(top, d):
        return (d in exclude_dir_names or
                os.path.normpath(os.path.join(top, d).lower()) in exclude_full_paths)

    for top, dirs, files in os.walk('.', topdown=True):
        dirs[:] = [ d for d in dirs if not is_excluded(top, d) ]
        for file in files:
            yield os.path.join(top, file)


# Disallow certain pattern in source files, with exceptions
def disallow(pat, exclude = []):
    print("==== Searching for '{}':".format(pat))
    pat = re.compile(pat)

    found_re = False
    for path in rs_sources(exclude):
        with open(path, 'r', encoding='utf-8') as file:
            for (line_num, line) in enumerate(file, start = 1):
                line = line.rstrip()
                if pat.search(line):
                    found_re = True
                    print("{}:{}:{}".format(path, line_num, line))

    print()
    return not found_re


# Check we depend on only one version of given crate
def check_crate_version_unique(crate_name):
    packages = toml.load('Cargo.lock')['package']
    versions = [ p['version'] for p in packages if p['name'] == crate_name ]

    if len(versions) == 0:
        print("Crate missing: '{}'".format(crate_name))
    if len(versions) >= 2:
        print("Multiple versions of '{}': {}".format(crate_name, ', '.join(versions)))

    return len(versions) == 1


# Ensure that the versions in the workspace's Cargo.toml are consistent
def check_workspace_and_package_versions_equal():
    print("==== Ensuring workspace and package versions are equal in the workspace's Cargo.toml")
    root = toml.load('Cargo.toml')

    workspace_version = root['package']['version']
    package_version = root['workspace']['package']['version']

    result = workspace_version == package_version

    if not result:
        print("Workspace vs package versions mismatch in Cargo.toml: '{}' != '{}'".format(workspace_version, package_version))
    print()

    return result


# Retrieve an item from arbitrarily nested dicts given a list of keys.
# E.g. get_from_nested_dicts({'a': {'b': 1, 'c': 2}}, ['a', 'b']) will
# return 1.
def get_from_nested_dicts(nested_dicts, keys_list) -> bool:
    cur_dict = nested_dicts
    while keys_list:
        key = keys_list.pop(0)
        if key in cur_dict:
            cur_dict = cur_dict[key]
        else:
            return None

    return cur_dict


# Since 'dependencies', 'dev-dependencies' and 'workspace.dependencies'
# have the same structure, we check the versions the same way for all
# of them.
# Here 'root_node' is the root node of the Cargo.toml file,
# 'dependencies_name' is the name of the 'dependencies' node (may contain
# dots) and 'file_path' is the path of the Cargo.toml file, for logging.
def internal_check_dependency_versions(root_node, dependencies_name: str, file_path) -> bool:
    res = True

    # list of crates, whose version may not have a minor version or may have a patch version
    exempted_crates = [
        # left here as an example, remove if you ever add one crate that is exempt
        # 'ctor'
    ]

    # Names with dots actually represent paths inside the tree of nodes.
    dependencies_path = dependencies_name.split('.')

    deps = get_from_nested_dicts(root_node, dependencies_path)
    if deps is not None:
        for dep in deps:
            # skip exempted crates
            if dep in exempted_crates:
                continue

            # versions that looks like `tokio = { version = "1.2.3" }`
            if 'version' in deps[dep]:
                version = deps[dep]['version']
            # versions that looks like late `tokio = "1.2.3"`
            elif type(deps[dep]) == str:
                version = deps[dep]
            else:
                version = None

            if version is not None:
                if len(version.split('.')) < 2:
                    print((f"In {dependencies_name} of '{file_path}' "
                           f"{dep} doesn't have a minor version: {version}"))
                    res = False
                elif len(version.split('.')) > 2:
                    print((f"In {dependencies_name} of '{file_path}' "
                           f"{dep} has a patch version: {version}"))
                    res = False

    return res


# Ensure that the versions in all Cargo.toml have a minor version but not a patch version.
def check_dependency_versions_patch_version():
    print("==== Ensuring that all versions in Cargo.toml have a minor version but not a patch version")

    # list of files exempt from patch version check
    exempted_files = [
    ]

    result = True

    for path in cargo_toml_files():
        if any(fnmatch.fnmatch(os.path.abspath(path), os.path.abspath(exempted))
               for exempted in exempted_files):
            continue

        # load the file
        root = toml.load(path)

        # check dependencies
        intermediary_result = internal_check_dependency_versions(root, 'dependencies', path)
        result = result and intermediary_result

        # check dev-dependencies
        intermediary_result = internal_check_dependency_versions(root, 'dev-dependencies', path)
        result = result and intermediary_result

        # check workspace.dependencies
        intermediary_result = internal_check_dependency_versions(root, 'workspace.dependencies', path)
        result = result and intermediary_result

    print()

    return result


# Check crate versions
def check_crate_versions():
    print("==== Checking crate versions:")

    ok = all([
        check_crate_version_unique('parity-scale-codec'),
        check_crate_version_unique('parity-scale-codec-derive'),
    ])

    print()
    return ok


# Check license header in current project crates
def check_local_licenses():
    print("==== Checking local license headers:")

    # list of files exempted from license check
    exempted_files = [
        "./script/src/opcodes.rs",
        "./common/src/uint/internal_macros.rs",
        "./common/src/uint/endian.rs",
        "./common/src/uint/impls.rs",
        "./common/src/uint/mod.rs"
    ]

    template = re.compile('(?:' + r')\n(?:'.join(LICENSE_TEMPLATE) + ')')

    ok = True
    for path in rs_sources():
        if any(fnmatch.fnmatch(os.path.abspath(path), os.path.abspath(exempted))
               for exempted in exempted_files):
            continue

        with open(path, 'r', encoding='utf-8') as file:
            if not template.search(file.read()):
                ok = False
                print("{}: License missing or incorrect".format(path))

    print()
    return ok


# check TODO(PR) and FIXME instances
def check_todos():
    print("==== Checking TODO(PR) and FIXME instances:")

    # list of files exempted from checks
    exempted_files = [
    ]

    ok = True
    for path in itertools.chain(rs_sources(), cargo_config_files()):
        if any(fnmatch.fnmatch(os.path.abspath(path), os.path.abspath(exempted))
               for exempted in exempted_files):
            continue

        with open(path, 'r', encoding='utf-8') as file:
            file_data = file.read()
            if 'TODO(PR)' in file_data or 'FIXME' in file_data:
                ok = False
                print("{}: Found TODO(PR) or FIXME or todo!() instances".format(path))

    print()
    return ok


def file_ends_with_newline(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        file_data = file.read()
        if len(file_data) == 0:
            # Exclude empty files
            return True

        last_char = file_data[-1]
        if last_char == '\n':
            return True
    return False


def check_files_end_with_newline():
    print("==== Checking file endings with EOL:")

    # list of files exempted from checks
    exempted_files = [
        'wasm-wrappers/doc/*',
    ]

    ok = True
    for path in sources_with_extensions([".toml",".rs",".py",".js",".yml",".yaml",".json",".htm",".html"]):
        if any(fnmatch.fnmatch(os.path.abspath(path), os.path.abspath(exempted))
               for exempted in exempted_files):
            continue

        if file_ends_with_newline(path) is False:
            ok = False
            print("{}: File does not end with EOL".format(path))

    print()
    return ok


# Check for trailing whitespaces
def check_trailing_whitespaces():
    print("==== Checking for trailing whitespaces:")

    # list of files exempted from checks
    exempted_files = [
        'crypto/src/symkey/chacha20poly1305/XCHACHA20POLY1305_TEST_VECTORS.tv',
        'script/src/test/test_vectors_4opc.csv.gz',
        'wasm-wrappers/doc/*',
        'build-tools/assets/*',
        'build-tools/osx/DeveloperIDG2CA.cer'
    ]

    ok = True
    for path in all_files():
        if any(fnmatch.fnmatch(os.path.abspath(path), os.path.abspath(exempted))
               for exempted in exempted_files):
            continue

        with open(path, 'r', encoding='utf-8') as file:
            try:
                for line_idx, line in enumerate(file, start=1):
                    line = line.rstrip('\n\r')
                    if line != line.rstrip():
                        ok = False
                        print(f"{path}: trailing whitespaces at line {line_idx}")
            except:
                print(f"{path}: can't check for trailing whitespaces, "
                      "perhaps it should be in 'exempted_files'?")

    print()
    return ok


def run_checks():
    return all([
        disallow(SCALECODEC_RE, exclude = ['serialization/core', 'trezor-common']),
        disallow(JSONRPSEE_RE, exclude = ['rpc']),
        check_local_licenses(),
        check_crate_versions(),
        check_workspace_and_package_versions_equal(),
        check_dependency_versions_patch_version(),
        check_todos(),
        check_trailing_whitespaces(),
        check_files_end_with_newline()
    ])


if __name__ == '__main__':
    if not run_checks():
        sys.exit(1)
