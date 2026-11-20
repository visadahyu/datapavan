# The DNS lab's DoT servers (scripts/dnslab, W8): nginx's stream module ends TLS on port 853 and hands each
# connection's DNS over TCP to the way's backend responder, which so sees the client's own queries (padding and
# client subnet options included). The official Alpine image, pinned by digest; nginx and its stream module from
# Alpine's own repository at exact versions. The configuration is chosen by the service (dot.conf or
# resolver-dot.conf).
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache nginx=1.30.7-r0 nginx-mod-stream=1.30.7-r0 && apk info -v 2>/dev/null | sort > /etc/dnslab-packages
COPY dot.conf resolver-dot.conf /etc/dnslab/
ENTRYPOINT ["nginx", "-g", "daemon off;", "-c"]
