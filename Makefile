.PHONY: build_docker_images

# python scripts are requiring `python3.11-venv` and `python3-pip` installed
install-pip-dependencies:
	python3 -m venv env && . env/bin/activate && python3 -m pip install --upgrade pip && python3 -m pip install toml

build_docker_images: install-pip-dependencies
	. env/bin/activate && python3 build-tools/docker/build.py

push_docker_images: install-pip-dependencies
	. env/bin/activate && python3 build-tools/docker/build.py --build=false --push --latest
