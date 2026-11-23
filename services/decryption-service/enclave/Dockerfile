FROM rust:1.98.1-alpine3.24@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build

# The network the image is built for: devnet or mainnet.
ARG SPR_NETWORK
ENV SPR_NETWORK=${SPR_NETWORK}
ENV RUSTFLAGS='-C target-feature=+crt-static'
ENV CARGOFLAGS="--target x86_64-unknown-linux-musl --locked --release --package spr-tvc-decryption-service --bin spr-tvc-decryption-service"
ENV RELEASE_DIR='/build/x86_64-unknown-linux-musl/release'
ENV CARGO_TARGET_DIR='/build'

ADD . /src/
WORKDIR /src/services/decryption-service/

RUN cargo fetch --locked --target x86_64-unknown-linux-musl
RUN --network=none <<-EOF
    set -eu
    case "${SPR_NETWORK}" in devnet|mainnet) ;; *) echo "--build-arg SPR_NETWORK=devnet|mainnet" >&2; exit 1 ;; esac
    cargo build ${CARGOFLAGS}
    mkdir -p /rootfs
    mv ${RELEASE_DIR}/spr-tvc-decryption-service /rootfs/tvc_app
    sha256sum /rootfs/tvc_app | awk '{print "SHA256=" $1}'
EOF

FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374 AS package
COPY --from=build /rootfs/. /

LABEL org.opencontainers.image.title="spr-tvc-decryption-service" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'
