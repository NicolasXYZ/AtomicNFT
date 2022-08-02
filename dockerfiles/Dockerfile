FROM baiduxlab/sgx-rust:1804-1.1.3

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --yes openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

EXPOSE 22