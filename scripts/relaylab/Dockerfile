# SPDX-License-Identifier: Apache-2.0
# The relay lab (scripts/relaylab.sh, ADR 0055): Debian 13's own caddy package, the version the project's server
# runs, with curl and openssl for the test's client, and the lab's target stand-in (stub.go) built in the official
# Go image. Both images pinned by digest; the package pinned by its version.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS stub
COPY stub.go /src/stub.go
RUN cd /src && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -o /usr/local/bin/relaylab-stub stub.go

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG CADDY_VERSION=2.6.2-12+deb13u1
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq -y install --no-install-recommends \
        "caddy=$CADDY_VERSION" curl ca-certificates openssl >/dev/null && \
    rm -rf /var/lib/apt/lists/*
COPY --from=stub /usr/local/bin/relaylab-stub /usr/local/bin/relaylab-stub
COPY run-caddy systemctl /usr/local/bin/
