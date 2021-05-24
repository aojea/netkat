generate:
	go get github.com/cilium/ebpf/cmd/bpf2go
	go generate

build:
	go build