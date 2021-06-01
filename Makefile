docker:
	docker build -t aojea/ebpf-generate -f Dockerfile .

generate:
	docker run -v $$(pwd):/target aojea/ebpf-generate bash -c "cd /target && go generate"

build:
	mkdir -p bin
	docker run -v $$(pwd):/target aojea/ebpf-generate bash -c "cd /target && CGO_ENABLED=0 go build -o bin/netkat"

image: build
	docker build -t aojea/netkat -f Dockerfile.netkat .

test:
	cd tests && bats tests.bats

clean:
	rm -rf bin

all: docker generate build
