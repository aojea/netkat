# xref: https://github.com/asavie/xdp/blob/2936ad5fb51b4e81240dbff1972af77f17d09984/examples/dumpframes/ebpf/Dockerfile
FROM centos:8

RUN dnf install -y make cmake gcc gdb clang llvm \
    clang-devel llvm-devel autoconf libtool kernel-devel \
    libbpf elfutils-libelf-devel elfutils-devel

RUN /bin/bash -c " \
    curl -fsSL https://golang.org/dl/go1.16.4.linux-amd64.tar.gz -o /tmp/golang.tar.gz && \
    tar -C /usr/local -xzf /tmp/golang.tar.gz"

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin/

RUN dnf -y install git

RUN go get github.com/cilium/ebpf/cmd/bpf2go@v0.6.0
