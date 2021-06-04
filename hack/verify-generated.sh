#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

git status --porcelain=v1
if [[ $(git status --porcelain) ]]; then
    git diff
    exit 1
fi
