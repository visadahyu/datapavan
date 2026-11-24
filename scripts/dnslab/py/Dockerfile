# The DNS lab's own Python services (scripts/dnslab, W8): the backend DNS responders (dnsserver.py), the censor
# (censor.py) and the captive portal (portal.py), Python's standard library only. Debian 13's slim image, pinned by
# digest, with Python from that image's own Debian snapshot at an exact version. `ctl` runs the control command of
# the service's own program (DNSLAB_ROLE: censor or portal).
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
        apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3=3.13.5-1 && break; \
        [ "$attempt" -lt 3 ]; sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort > /etc/dnslab-packages
COPY dnsserver.py censor.py portal.py /opt/dnslab/
RUN printf '#!/bin/sh\nexec python3 -I "/opt/dnslab/${DNSLAB_ROLE:?no role}.py" ctl "$@"\n' > /usr/local/bin/ctl && \
    chmod 755 /usr/local/bin/ctl
