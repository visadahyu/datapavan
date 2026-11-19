# The interoperation lab's WireGuard peer (W7's spike, ADR 0035): the Linux kernel's WireGuard, set up with
# Alpine's own `wg` and `ip`, and behind its interface ICMP echo (the kernel's), a UDP echo, a reflector that
# answers from outside the client's AllowedIPs, and an HTTP server (services.py, Python's standard library).
# The official Alpine image, pinned by digest; packages from Alpine's own repository only. The versions
# installed are listed in /etc/wglab-packages.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache wireguard-tools-wg iproute2 python3 && apk info -v 2>/dev/null | sort > /etc/wglab-packages
COPY start.sh services.py /opt/wglab/
ENTRYPOINT ["/bin/sh", "/opt/wglab/start.sh"]
