import os
import sys
import tomllib

def read_cargo_toml(file_path):
    with open(file_path, "rb") as cargo_toml_file:
        cargo_toml = tomllib.load(cargo_toml_file)
    return cargo_toml

def get_package_name(crate_dir):
    cargo_toml_path = os.path.join(crate_dir, "Cargo.toml")
    cargo_toml = read_cargo_toml(cargo_toml_path)

    if cargo_toml is not None:
        package = cargo_toml.get("package", {})
        return package.get("name", None)
    else:
        raise Exception("Cargo.toml not found for crate {}.".format(crate_dir))

def group_crates_by_first_directory(members, do_group: bool):
    '''
    Here we ensure that all crates in the same directory are grouped together, to minimize fracturing of coverage.
    We assume here that crates are tested within their directory. This is a fair assumption since we put test-suites
    in the same directory as the crate they are testing.

    This can be disabled with do_group boolean. In that case, groups will be the same crate dirs.
    '''

    if do_group:
        crate_groups = {}
        for crate_dir in members:
            # Split the path name with the directory separator
            dir_parts = crate_dir.split(os.path.sep)
            if dir_parts:
                # Group crates by the first element and join them back using the separator
                dir_name = os.path.sep.join(dir_parts[:1])
                if dir_name not in crate_groups:
                    crate_groups[dir_name] = []
                crate_groups[dir_name].append(crate_dir)
    else:
        crate_groups = {}
        for crate_dir in members:
            crate_groups[crate_dir] = []
            crate_groups[crate_dir].append(crate_dir)
    return crate_groups

def partition_workspace(m, n):
    cargo_toml = read_cargo_toml("Cargo.toml")

    if cargo_toml is None:
        raise Exception("Cargo.toml not found.")

    workspace = cargo_toml.get("workspace", {})
    members = workspace.get("members", [])

    if not members:
        raise Exception("No members found in the workspace.")

    # Group crates based on directory structure using directory separators
    # This was disabled because we still are having disk-space issues
    crate_directory_groups = group_crates_by_first_directory(members, False)

    # Calculate elements per partition and remainder based on the number of crate directories
    total_directories = len(crate_directory_groups)
    elements_per_partition = total_directories // m
    remainder = total_directories % m

    # Calculate the start and end indices for the current partition
    start_idx = n * elements_per_partition + min(n, remainder)
    end_idx = start_idx + elements_per_partition + (1 if n < remainder else 0)

    # Get the crate directories for the current partition
    partition_directories = []
    for dir_path in list(crate_directory_groups.keys())[start_idx:end_idx]:
        partition_directories.extend(crate_directory_groups[dir_path])

    # Get the package names from the crate directories in this partition
    package_names = [get_package_name(crate_dir) for crate_dir in partition_directories]

    return package_names

if __name__ == "__main__":
    if len(sys.argv) == 2 and (sys.argv[1] == "--help" or sys.argv[1] == "-h"):
        print("Usage: python partition_workspace.py <total_partitions> <partition_index> [prefix]")
        print("")
        print("Partitions the workspace into m partitions and returns the crates in the n-th partition.")
        print("This can be used to split the workload of running tests across multiple CI jobs.")
        print("")
        print("To run the tests for the n-th partition, use the following command (for 3 partitions):")
        print("---")
        print("python3 {} 3 0 -p | xargs cargo test".format(sys.argv[0]))
        print("python3 {} 3 1 -p | xargs cargo test".format(sys.argv[0]))
        print("python3 {} 3 2 -p | xargs cargo test".format(sys.argv[0]))
        print("---")
        sys.exit(1)

    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python3 {} <total_partitions> <partition_index> [prefix]".format(sys.argv[0]))
        sys.exit(1)

    total_splits = int(sys.argv[1])
    partition_index = int(sys.argv[2])
    prefix = sys.argv[3] + " " if len(sys.argv) == 4 else ""

    if total_splits <= 0 or partition_index < 0 or partition_index >= total_splits:
        print("Invalid input.")
        sys.exit(1)

    partition = partition_workspace(total_splits, partition_index)
    partition_with_prefix = [prefix + member for member in partition]

    print("{}".format(" ".join(partition_with_prefix)))
