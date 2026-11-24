# SPDX-License-Identifier: Apache-2.0
# The relay lab (scripts/relaylab.sh, ADR 0055): Debian 13's own caddy package, the version the project's server
# runs, with curl and openssl for the test's client, and the lab's target stand-in (stub.go) built in the official
# Go image. Both images pinned by digest. The packages come from the Debian image's own snapshot, which never changes,
# with caddy at its version: the live archive drops a package's version at its next update (the DNS lab's drift, CI
# run 45354185822).
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS stub
COPY stub.go /src/stub.go
RUN cd /src && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -o /usr/local/bin/relaylab-stub stub.go

FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG CADDY_VERSION=2.6.2-12+deb13u1
ENV DEBIAN_FRONTEND=noninteractive
# The image's sources name in a comment the snapshot its own packages came from; apt reads only that snapshot.
RUN set -eu; \
    sources=/etc/apt/sources.list.d/debian.sources; \
    sed -i -e '/^URIs: /d' -e 's|^# \(http://snapshot\.debian\.org/archive/[a-z-]*/[0-9]*T[0-9]*Z\)$|URIs: \1|' "$sources"; \
    [ "$(grep -c '^URIs: http://snapshot\.debian\.org/archive/' "$sources")" = 2 ] || { cat "$sources"; exit 1; }; \
    for attempt in 1 2 3; do \
        apt-get -qq -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update && \
        apt-get -qq -o Acquire::Retries=3 install -y --no-install-recommends \
            "caddy=$CADDY_VERSION" curl ca-certificates openssl >/dev/null && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*
COPY --from=stub /usr/local/bin/relaylab-stub /usr/local/bin/relaylab-stub
COPY run-caddy systemctl /usr/local/bin/
