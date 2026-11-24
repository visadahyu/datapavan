# The DNS lab's DoT servers (scripts/dnslab, W8): nginx's stream module ends TLS on port 853 and hands each
# connection's DNS over TCP to the way's backend responder, which so sees the client's own queries (padding and
# client subnet options included). Debian 13's slim image, pinned by digest, with nginx and its stream module from
# that image's own Debian snapshot at exact versions. The configuration is chosen by the service (dot.conf or
# resolver-dot.conf).
FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ENV DEBIAN_FRONTEND=noninteractive
# The image's sources name in a comment the snapshot its own packages came from; apt reads only that snapshot, so the
# packages keep their exact versions for as long as the image's digest stands (the proxy lab's way: Alpine keeps one
# build of each package, and a rebuild dropped the one pinned here, CI run 45354185822).
RUN set -eu; \
    sources=/etc/apt/sources.list.d/debian.sources; \
    sed -i -e '/^URIs: /d' -e 's|^# \(http://snapshot\.debian\.org/archive/[a-z-]*/[0-9]*T[0-9]*Z\)$|URIs: \1|' "$sources"; \
    [ "$(grep -c '^URIs: http://snapshot\.debian\.org/archive/' "$sources")" = 2 ] || { cat "$sources"; exit 1; }; \
    for attempt in 1 2 3; do \
        apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update && \
        apt-get -o Acquire::Retries=3 install -y --no-install-recommends nginx=1.26.3-3+deb13u10 libnginx-mod-stream=1.26.3-3+deb13u10 && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort > /etc/dnslab-packages
COPY dot.conf resolver-dot.conf /etc/dnslab/
ENTRYPOINT ["nginx", "-g", "daemon off;", "-c"]
