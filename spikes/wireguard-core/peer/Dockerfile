# The interoperation lab's WireGuard peer (W7's spike, ADR 0035; both references since W7, part 3a): one image for
# the two reference implementations, chosen by WGLAB_IMPL at start (start.sh). The Linux kernel's WireGuard (the
# module is the host's) or wireguard-go, a second code base by WireGuard's authors, the one WireGuard's own Android
# app and Proton's apps run; each set up with `wg` and `ip`, and behind the interface ICMP echo (the container's
# kernel), a UDP echo, a reflector that answers from outside the client's AllowedIPs, and an HTTP server
# (services.py, Python's standard library).
#
# Nothing unpinned: Go's and Debian's official images by digest; wireguard-go at a pinned commit, its module checked
# against the checksum written here (which Go's checksum database holds too), its dependencies against its go.sum,
# and built with -trimpath; Debian's packages from snapshot.debian.org at the moment the Debian image was made, which
# the image names in its own sources, each at the version written here. Every fetch is tried three times. The
# versions are listed in /etc/wglab-packages and /etc/wglab-wireguard-go.
#
# wireguard-go carries one fix of ours, upstream's own proposal, open there since 2025-12-20
# (wireguard-go-ipv6-send.patch): without it the peer sends to a wrong IPv6 address once it has sent over IPv4, which
# the lab's server at an IPv6 address met in 4 of 6 runs (ADR 0035, "How it is built (W7, part 3a)").

# Debian's flavour of Go's image, for its git, which applies the patch.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS wireguard-go
# wireguard-go's last commit, b3bc704 of 2026-10-24 ("device: don't overflow uint16 when adding v4 header length"),
# after 2631ce9 of 2026-10-06 ("device: noise: reject response consumption after intermediate initiation").
ARG WIREGUARD_GO=v0.0.0-20261024220952-b3bc704ef0ee
ARG WIREGUARD_GO_SUM=h1:hByBPN/P/BVzJ591rJfvNhdoL94vmBtRbnVw77QJL20=
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -mod=readonly" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
COPY wireguard-go-ipv6-send.patch /tmp/
RUN set -eu; \
    for attempt in 1 2 3; do \
        go mod download -json "golang.zx2c4.com/wireguard@$WIREGUARD_GO" >/tmp/module.json && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    grep -q "\"Sum\": \"$WIREGUARD_GO_SUM\"" /tmp/module.json || { cat /tmp/module.json; exit 1; }; \
    cp -r "$(sed -n 's/^\t"Dir": "\(.*\)",$/\1/p' /tmp/module.json)" /src; \
    chmod -R u+w /src; \
    cd /src; \
    git apply --verbose /tmp/wireguard-go-ipv6-send.patch; \
    for attempt in 1 2 3; do \
        go build -ldflags='-s -w -buildid=' -o /wireguard-go . && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    printf 'wireguard-go %s %s with wireguard-go-ipv6-send.patch (upstream pull request 135), built with %s\n' \
        "$WIREGUARD_GO" "$WIREGUARD_GO_SUM" "$(go version)" >/wireguard-go.version

FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ENV DEBIAN_FRONTEND=noninteractive
# The image's sources name in a comment the snapshot its own packages came from; apt reads only that snapshot.
# Its Release files carry a date after which apt would refuse them, long past for a snapshot; their signatures are
# checked as always.
RUN set -eu; \
    sources=/etc/apt/sources.list.d/debian.sources; \
    sed -i -e '/^URIs: /d' -e 's|^# \(http://snapshot\.debian\.org/archive/[a-z-]*/[0-9]*T[0-9]*Z\)$|URIs: \1|' "$sources"; \
    [ "$(grep -c '^URIs: http://snapshot\.debian\.org/archive/' "$sources")" = 2 ] || { cat "$sources"; exit 1; }; \
    for attempt in 1 2 3; do \
        apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update && \
        apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
            wireguard-tools=1.0.20210914-3 iproute2=6.15.0-1 python3=3.13.5-1 && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort >/etc/wglab-packages
COPY --from=wireguard-go /wireguard-go /usr/local/bin/wireguard-go
COPY --from=wireguard-go /wireguard-go.version /etc/wglab-wireguard-go
COPY start.sh services.py /opt/wglab/
ENTRYPOINT ["/bin/sh", "/opt/wglab/start.sh"]
