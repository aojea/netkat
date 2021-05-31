docker:
	docker build -t aojea/ebpf-generate -f Dockerfile .

generate:
	docker run -i -t -v $$(pwd):/target aojea/ebpf-generate bash -c "cd /target && go generate"

build:
	mkdir -p bin
	docker run -i -t -v $$(pwd):/target aojea/ebpf-generate bash -c "cd /target && go build -o bin/netkat"

clean:
	rm -rf bin

all: docker generate build
