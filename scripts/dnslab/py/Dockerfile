# The DNS lab's own Python services (scripts/dnslab, W8): the backend DNS responders (dnsserver.py), the censor
# (censor.py) and the captive portal (portal.py), Python's standard library only. The official Alpine image,
# pinned by digest; Python from Alpine's own repository at an exact version. `ctl` runs the control command of
# the service's own program (DNSLAB_ROLE: censor or portal).
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache python3=3.14.10-r2 && apk info -v 2>/dev/null | sort > /etc/dnslab-packages
COPY dnsserver.py censor.py portal.py /opt/dnslab/
RUN printf '#!/bin/sh\nexec python3 -I "/opt/dnslab/${DNSLAB_ROLE:?no role}.py" ctl "$@"\n' > /usr/local/bin/ctl && \
    chmod 755 /usr/local/bin/ctl
