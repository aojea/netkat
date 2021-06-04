# enable modules
GO111MODULE=on
# disable CGO by default for static binaries
CGO_ENABLED=0
# Use current hash to tag the container images
COMMIT:=$(shell git rev-parse --short HEAD 2>/dev/null)
TAG_GENERATE_IMAGE?=$(COMMIT)
export GO111MODULE CGO_ENABLED TAG_GENERATE_IMAGE

generate:
	hack/update-generated.sh

build:
	mkdir -p bin
	docker run -v $$(pwd):/target aojea/ebpf-generate:$(TAG_GENERATE_IMAGE) bash -c "cd /target && CGO_ENABLED=0 go build -o bin/netkat"

image: build
	docker build --no-cache -t aojea/netkat:$(COMMIT) -f Dockerfile.netkat .

test:
	cd tests && bats tests.bats

verify:
	hack/verify-generated.sh

clean:
	rm -rf bin

all: generate build
