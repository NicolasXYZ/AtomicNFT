#!/usr/bin/env bash

set -euo pipefail

CONTAINER_NAME=dcnet-new
DOCKER_IMAGE=baiduxlab/sgx-rust:1804-1.1.3

if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
  docker start -ai $CONTAINER_NAME
else
  docker run \
    -v $PWD:/root/sgx \
    -ti \
    --hostname $CONTAINER_NAME \
    --name $CONTAINER_NAME \
    -e SGX_MODE=SW \
    $DOCKER_IMAGE
fi
