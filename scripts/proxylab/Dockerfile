# W8 part 2a's proxy lab (ADR 0052; scripts/proxylab.sh): one image for the lab's SOCKS5 server (microsocks: Dante left
# Debian with trixie), its HTTP proxies (tinyproxy, and squid for the network's own proxy: the proxy record's
# forwarder), its target (target.py, Python's standard library) and its front (socat), chosen by the command each service of
# compose.yaml runs; and mtg, an MTProto proxy, built from its release at a pinned commit.
#
# Nothing unpinned, as the WireGuard lab's image (spikes/wireguard-core/peer/Dockerfile): Go's and Debian's official
# images by digest; mtg's module checked against the checksum written here (which Go's checksum database holds too),
# its dependencies against its go.sum, built with -trimpath; Debian's packages from snapshot.debian.org at the moment
# the Debian image was made, each at the version written here. Every fetch is tried three times. The versions are
# listed in /etc/proxylab-packages and /etc/proxylab-mtg.

FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS mtg
# mtg v2.3.0, commit 5899a2f5b3bda263a885c3da450388a198f67cda.
ARG MTG=v2.3.0
ARG MTG_SUM=h1:jnkr7C7duMjOeDnAx8cmBVUlzkpXR3cVWmayKyAXbms=
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -mod=readonly" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN set -eu; \
    for attempt in 1 2 3; do \
        go mod download -json "github.com/9seconds/mtg/v2@$MTG" >/tmp/module.json && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    grep -q "\"Sum\": \"$MTG_SUM\"" /tmp/module.json || { cat /tmp/module.json; exit 1; }; \
    cp -r "$(sed -n 's/^\t"Dir": "\(.*\)",$/\1/p' /tmp/module.json)" /src; \
    chmod -R u+w /src; \
    cd /src; \
    for attempt in 1 2 3; do \
        go build -ldflags='-s -w -buildid=' -o /mtg . && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    printf 'mtg %s %s, built with %s\n' "$MTG" "$MTG_SUM" "$(go version)" >/mtg.version

FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ENV DEBIAN_FRONTEND=noninteractive
# The image's sources name in a comment the snapshot its own packages came from; apt reads only that snapshot.
RUN set -eu; \
    sources=/etc/apt/sources.list.d/debian.sources; \
    sed -i -e '/^URIs: /d' -e 's|^# \(http://snapshot\.debian\.org/archive/[a-z-]*/[0-9]*T[0-9]*Z\)$|URIs: \1|' "$sources"; \
    [ "$(grep -c '^URIs: http://snapshot\.debian\.org/archive/' "$sources")" = 2 ] || { cat "$sources"; exit 1; }; \
    for attempt in 1 2 3; do \
        apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update && \
        apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
            microsocks=1.0.5-1 tinyproxy=1.11.2-1 socat=1.8.0.3-1+deb13u1 python3=3.13.5-1 \
            squid=6.13-2+deb13u4 && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort >/etc/proxylab-packages
# squid runs Debian's shipped configuration with one change: the lab's network, which squid.conf's own localnet list
# holds, allowed by the line Debian's conf.d/debian.conf leaves commented ("only allow localhost ... on new installs").
# Everything else is Debian's default: CONNECT only to SSL_ports (443), requests only to Safe_ports. A step of its own,
# after the install, so that scripts/lab-pins.py's simulated install runs nothing that needs squid.
RUN set -eu; \
    sed -i 's|^#http_access allow localnet$|http_access allow localnet|' /etc/squid/conf.d/debian.conf; \
    [ "$(grep -c '^http_access allow localnet$' /etc/squid/conf.d/debian.conf)" = 1 ]; \
    grep -q '^acl localnet src 172.16.0.0/12' /etc/squid/squid.conf
COPY --from=mtg /mtg /usr/local/bin/mtg
COPY --from=mtg /mtg.version /etc/proxylab-mtg
COPY start.sh target.py /opt/proxylab/
ENTRYPOINT ["/bin/sh", "/opt/proxylab/start.sh"]
