import toml
import os
import subprocess
import argparse


def get_cargo_version(cargo_toml_path):
    if not os.path.exists(cargo_toml_path):
        raise ValueError(f"No such file: {cargo_toml_path}")

    # Read the Cargo.toml file
    config = toml.load(cargo_toml_path)

    # Get the version
    version = config.get('package', {}).get('version')

    if version is None:
        raise ValueError(f"No version specified in {cargo_toml_path}")

    return version


def build_docker_image(dockerfile_path, image_name, tags, num_jobs=None):
    # Docker build command
    command = f"docker build"

    full_tags = [image_name] if len(tags) == 0 else [f"{image_name}:{tag}" for tag in tags];

    for full_tag in full_tags:
        command += f" -t {full_tag}"

    command += f" -f {dockerfile_path}"

    if num_jobs:
        command += f" --build-arg NUM_JOBS={num_jobs}"

    # Force the amd64 platform in case we're building on an arm-based one.
    command += " --platform linux/amd64"

    # Note: "plain" output is more verbose, but it makes it easier to understand what went wrong
    # when a problem occurs.
    command += " --progress=plain"
    command += " ."

    try:
        # Run the command
        subprocess.check_call(command, shell=True)
        print(f"Built {image_name} successfully (the tags are: {full_tags}).")
    except Exception as error:
        print(f"Error occurred: {error}")
        exit(1) # stop the build


def push_docker_image(image_name, version, latest=False):
    # Docker tag command
    full_image_name = f"{image_name}:{version}"
    if latest:
        latest_image_name = f"{image_name}:latest"
        tag_command = f"docker tag {full_image_name} {latest_image_name}"
        subprocess.check_call(tag_command, shell=True)

    # Docker push command
    push_command = f"docker push {full_image_name}"
    subprocess.check_call(push_command, shell=True)

    # if latest flag is true, push the image with 'latest' tag
    if latest:
        push_command_latest = f"docker push {latest_image_name}"
        subprocess.check_call(push_command_latest, shell=True)

    print(f"Pushed {full_image_name} successfully.")
    if latest:
        print(f"Pushed {latest_image_name} successfully.")


def delete_docker_image(image_name, version):
    # Full image name
    full_image_name = f"{image_name}:{version}"

    # Docker rmi command
    command = f"docker rmi {full_image_name}"

    # Run the command
    try:
        subprocess.check_call(command, shell=True)
        print(f"Deleted {full_image_name} successfully.")
    except subprocess.CalledProcessError:
        print(f"Failed to delete {full_image_name}.")


def build_instances(tags, docker_hub_user, num_jobs):
    build_docker_image("build-tools/docker/Dockerfile.builder",
                        "mintlayer-builder", ["latest"], num_jobs)
    build_docker_image("build-tools/docker/Dockerfile.runner-base",
                        "mintlayer-runner-base", ["latest"], num_jobs)

    build_docker_image("build-tools/docker/Dockerfile.node-daemon",
                        f"{docker_hub_user}/node-daemon", tags)
    build_docker_image("build-tools/docker/Dockerfile.api-blockchain-scanner-daemon",
                        f"{docker_hub_user}/api-blockchain-scanner-daemon", tags)
    build_docker_image("build-tools/docker/Dockerfile.api-web-server",
                        f"{docker_hub_user}/api-web-server", tags)
    build_docker_image("build-tools/docker/Dockerfile.wallet-cli",
                        f"{docker_hub_user}/wallet-cli", tags)
    build_docker_image("build-tools/docker/Dockerfile.wallet-rpc-daemon",
                        f"{docker_hub_user}/wallet-rpc-daemon", tags)
    build_docker_image("build-tools/docker/Dockerfile.dns-server",
                        f"{docker_hub_user}/dns-server", tags)
#    delete_docker_image("mintlayer-builder", "latest")


def push_instances(docker_hub_user, version, latest):
    push_docker_image(f"{docker_hub_user}/node-daemon", version, latest)
    push_docker_image(f"{docker_hub_user}/api-blockchain-scanner-daemon", version, latest)
    push_docker_image(f"{docker_hub_user}/api-web-server", version, latest)
    push_docker_image(f"{docker_hub_user}/wallet-cli", version, latest)
    push_docker_image(f"{docker_hub_user}/wallet-rpc-daemon", version, latest)
    push_docker_image(f"{docker_hub_user}/dns-server", version, latest)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--push', action='store_true', help='Push the Docker image to Docker Hub')
    parser.add_argument('--docker-hub-user', help='Docker Hub username', default='mintlayer')
    parser.add_argument('--latest', action='store_true', help='Tag the Docker image as latest while pushing')
    parser.add_argument('--build', type=lambda x: (str(x).lower() == 'true'), default=True, help="Set to false avoid the build")
    parser.add_argument('--version', help='Override version number', default=None)
    parser.add_argument('--num_jobs', help='Number of parallel jobs', default=(os.cpu_count() or 1))
    parser.add_argument('--local_tags', nargs='*', help='Additional tags to apply (these won\'t be pushed)', default=[])
    args = parser.parse_args()

    version = args.version if args.version else get_cargo_version("Cargo.toml")
    # Note: the CI currently takes the version from the release tag, so it always starts with "v",
    # but the version from Cargo.toml doesn't have this prefix.
    version = version if version.startswith('v') else f"v{version}"

    tags = [version, *args.local_tags]

    if args.build:
        build_instances(tags, args.docker_hub_user, args.num_jobs)

    # Only push the image if the --push flag is provided
    if args.push:
        push_instances(args.docker_hub_user, version, args.latest)


if __name__ == "__main__":
    main()
