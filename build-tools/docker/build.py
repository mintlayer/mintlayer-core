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


def build_docker_image(dockerfile_path, image_name, version, num_jobs=None):
    # Docker build command
    command = f"docker build -t {image_name}:{version} -f {dockerfile_path}"
    if num_jobs:
        command += f" --build-arg NUM_JOBS={num_jobs}"
    command += " ."

    try:
        # Run the command
        subprocess.check_call(command, shell=True)
        print(f"Built {image_name}:{version} successfully.")
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


def build_instances(version, num_jobs=None):
    build_docker_image("build-tools/docker/Dockerfile.builder", "mintlayer-builder", "latest", num_jobs)
    build_docker_image("build-tools/docker/Dockerfile.node-daemon", "mintlayer/node-daemon", version)
    build_docker_image("build-tools/docker/Dockerfile.node-gui", "mintlayer/node-gui", version)
    build_docker_image("build-tools/docker/Dockerfile.wallet-cli", "mintlayer/wallet-cli", version)
    delete_docker_image("mintlayer-builder", "latest")


def push_instances(version, latest):
    push_docker_image("mintlayer/node-daemon",version , latest)
    push_docker_image("mintlayer/node-gui",version , latest)
    push_docker_image("mintlayer/wallet-cli",version , latest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--push', action='store_true', help='Push the Docker image to Docker Hub')
    parser.add_argument('--latest', action='store_true', help='Tag the Docker image as latest while pushing')
    parser.add_argument('--build', type=lambda x: (str(x).lower() == 'true'), default=True, help="Set to false avoid the build")
    parser.add_argument('--version', help='Override version number', default=None)
    parser.add_argument('--num_jobs', help='Number of parallel jobs, defaults to # of CPUs', default=None)
    args = parser.parse_args()

    version = args.version if args.version else get_cargo_version("Cargo.toml")

    if args.build:
        build_instances(version, args.num_jobs)

    # Only push the image if the --push flag is provided
    if args.push:
        latest = args.latest
        push_instances(version, latest)


if __name__ == "__main__":
    main()
