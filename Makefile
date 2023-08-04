.PHONY: build_docker_images

install-pip-dependencies:
	python3 -m pip install --upgrade pip
	python3 -m pip install toml
	
build_docker_images: install-pip-dependencies
	python3 build-tools/docker/build.py
