import sys
import toml
import os

def read_cargo_toml(file_path):
    with open(file_path, "r") as cargo_toml_file:
        cargo_toml = toml.load(cargo_toml_file)
    return cargo_toml

def get_package_name(crate_dir):
    cargo_toml_path = os.path.join(crate_dir, "Cargo.toml")
    cargo_toml = read_cargo_toml(cargo_toml_path)

    if cargo_toml is not None:
        package = cargo_toml.get("package", {})
        return package.get("name", None)
    else:
        raise Exception("Cargo.toml not found for crate {}.".format(crate_dir))

def partition_workspace(m, n):
    cargo_toml = read_cargo_toml("Cargo.toml")

    if cargo_toml is None:
        raise Exception("Cargo.toml not found.")

    workspace = cargo_toml.get("workspace", {})
    members = workspace.get("members", [])

    if not members:
        raise Exception("No members found in the workspace.")

    total_members = len(members)
    elements_per_partition = total_members // m
    remainder = total_members % m

    start_idx = n * elements_per_partition + min(n, remainder)
    end_idx = start_idx + elements_per_partition + (1 if n < remainder else 0)

    partition = members[start_idx:end_idx]

    package_names = [get_package_name(crate_dir) for crate_dir in partition]

    return package_names

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python partition_workspace.py <total_splits> <partition_index> [prefix]")
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
