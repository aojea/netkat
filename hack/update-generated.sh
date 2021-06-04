#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

TAG=${TAG_GENERATE_IMAGE:-latest}
echo "Using image aojea/ebpf-generate:${TAG}"

# Check if image already exist or build it
if ! docker pull aojea/ebpf-generate:${TAG} ; then
    docker build -t aojea/ebpf-generate:${TAG} -f Dockerfile .
fi

# Generate eBPF code
docker run -v $PWD:/target aojea/ebpf-generate:${TAG} \
    bash -c "cd /target && CGO_ENABLED=0 go generate"
