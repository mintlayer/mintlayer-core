import argparse
import os
import pathlib
import subprocess
import tomllib


ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
ROOT_CARGO_TOML = ROOT_DIR.joinpath("Cargo.toml")


def get_cargo_version(cargo_toml_path):
    if not os.path.exists(cargo_toml_path):
        raise ValueError(f"No such file: {cargo_toml_path}")

    # Read the Cargo.toml file
    with open(cargo_toml_path, "rb") as file:
        config = tomllib.load(file)

    # Get the version
    version = config.get('package', {}).get('version')

    if version is None:
        raise ValueError(f"No version specified in {cargo_toml_path}")

    return version


def apply_tag_suffix(tags, tag_suffix):
    # Append the suffix (e.g. "arm64") to every tag, so that images built for a
    # non-default architecture never overwrite the tags of the default-arch images.
    if not tag_suffix:
        return list(tags)
    return [f"{tag}-{tag_suffix}" for tag in tags]


def build_docker_image(dockerfile_path, image_name, tags, num_jobs=None, platform="amd64", tag_suffix=None):
    raw_tags = list(tags)
    tags = apply_tag_suffix(raw_tags, tag_suffix)

    # Docker build command
    command = f"docker build"

    full_tags = [image_name] if len(tags) == 0 else [f"{image_name}:{tag}" for tag in tags];

    for full_tag in full_tags:
        command += f" -t {full_tag}"

    command += f" -f {dockerfile_path}"

    if num_jobs:
        command += f" --build-arg NUM_JOBS={num_jobs}"

    command += f" --platform linux/{platform}"

    # Note: "plain" output is more verbose, but it makes it easier to understand what went wrong
    # when a problem occurs.
    command += " --progress=plain"
    command += " ."

    try:
        # Run the command
        subprocess.check_call(command, shell=True, cwd=ROOT_DIR)
        print(f"Built {image_name} successfully (the tags are: {full_tags}).")
    except subprocess.CalledProcessError as error:
        print(f"Failed to build {image_name}: {error}")
        exit(1) # stop the build

    if tag_suffix:
        # The app images reference "mintlayer-builder:latest" / "mintlayer-runner-base"
        # without a suffix in their FROM lines. When building for a non-default
        # architecture, the suffixed base image exists locally but the unsuffixed tag
        # would be resolved from the registry (where only the amd64 variant exists).
        # Add a local unsuffixed alias pointing to the image we've just built, so the
        # subsequent app image builds resolve it locally. These local aliases are never
        # pushed (push_instances only pushes the suffixed tags), so they cannot
        # overwrite the registry's default-arch tags.
        local_alias = f"{image_name}:{raw_tags[0]}"
        alias_command = f"docker tag {full_tags[0]} {local_alias}"
        try:
            subprocess.check_call(alias_command, shell=True)
            print(f"Tagged {full_tags[0]} locally as {local_alias}.")
        except subprocess.CalledProcessError as error:
            print(f"Failed to tag {image_name}: {error}")
            exit(1) # stop the build


def push_docker_image(image_name, tags):
    for tag in tags:
        full_image_name = f"{image_name}:{tag}"
        push_command = f"docker push {full_image_name}"

        try:
            subprocess.check_call(push_command, shell=True)
            print(f"Pushed {full_image_name} successfully.")
        except subprocess.CalledProcessError as error:
            print(f"Failed to push {full_image_name}: {error}")
            exit(1) # stop the build


def delete_docker_image(image_name, version):
    # Full image name
    full_image_name = f"{image_name}:{version}"

    # Docker rmi command
    command = f"docker rmi {full_image_name}"

    # Run the command
    try:
        subprocess.check_call(command, shell=True)
        print(f"Deleted {full_image_name} successfully.")
    except subprocess.CalledProcessError as error:
        print(f"Failed to delete {full_image_name}: {error}")
        # No need to fail the build here


def build_instances(tags, docker_hub_user, num_jobs, platform="amd64", tag_suffix=None):
    build_docker_image("build-tools/docker/Dockerfile.builder",
                        "mintlayer-builder", ["latest"], num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.runner-base",
                        "mintlayer-runner-base", ["latest"], num_jobs, platform, tag_suffix)

    build_docker_image("build-tools/docker/Dockerfile.node-daemon",
                        f"{docker_hub_user}/node-daemon", tags, num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.api-blockchain-scanner-daemon",
                        f"{docker_hub_user}/api-blockchain-scanner-daemon", tags, num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.api-web-server",
                        f"{docker_hub_user}/api-web-server", tags, num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.wallet-cli",
                        f"{docker_hub_user}/wallet-cli", tags, num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.wallet-rpc-daemon",
                        f"{docker_hub_user}/wallet-rpc-daemon", tags, num_jobs, platform, tag_suffix)
    build_docker_image("build-tools/docker/Dockerfile.dns-server",
                        f"{docker_hub_user}/dns-server", tags, num_jobs, platform, tag_suffix)
#    delete_docker_image("mintlayer-builder", "latest")


def push_instances(docker_hub_user, tags):
    push_docker_image(f"{docker_hub_user}/node-daemon", tags)
    push_docker_image(f"{docker_hub_user}/api-blockchain-scanner-daemon", tags)
    push_docker_image(f"{docker_hub_user}/api-web-server", tags)
    push_docker_image(f"{docker_hub_user}/wallet-cli", tags)
    push_docker_image(f"{docker_hub_user}/wallet-rpc-daemon", tags)
    push_docker_image(f"{docker_hub_user}/dns-server", tags)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--push', action='store_true', help='Push the Docker image to Docker Hub')
    parser.add_argument('--docker-hub-user', help='Docker Hub username', default='mintlayer')
    parser.add_argument('--latest', action='store_true', help='Tag the Docker image as latest')
    parser.add_argument('--build', type=lambda x: (str(x).lower() == 'true'), default=True, help="Set to false avoid the build")
    parser.add_argument('--version', help='Override version number', default=None)
    parser.add_argument('--num_jobs', help='Number of parallel jobs', default=(os.cpu_count() or 1))
    parser.add_argument('--local_tags', nargs='*', help='Additional tags to apply (these won\'t be pushed)', default=[])
    parser.add_argument('--platform', choices=['amd64', 'arm64'], default='amd64',
                        help='Target CPU architecture for the images (the default keeps the historical behavior)')
    parser.add_argument('--tag_suffix', help='Suffix appended to every built and pushed image tag (e.g. "arm64")',
                        default=None)
    args = parser.parse_args()

    version = args.version if args.version else get_cargo_version(ROOT_CARGO_TOML)
    # Note: the CI currently takes the version from the release tag, so it always starts with "v",
    # but the version from Cargo.toml doesn't have this prefix.
    version = version.removeprefix("v")

    # We want to push both "X.Y.Z" and "vX.Y.Z".
    tags_to_push = [version, f"v{version}"]
    if args.latest:
        tags_to_push.append("latest")

    all_tags = args.local_tags + tags_to_push

    if args.build:
        # Note: the suffix is applied inside build_docker_image, so it must NOT be
        # pre-applied to these tags (that would produce doubled suffixes).
        build_instances(all_tags, args.docker_hub_user, args.num_jobs,
                        args.platform, args.tag_suffix)

    # Only push the image if the --push flag is provided
    if args.push:
        push_instances(args.docker_hub_user, apply_tag_suffix(tags_to_push, args.tag_suffix))


if __name__ == "__main__":
    main()
