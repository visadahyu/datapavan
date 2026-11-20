# The DNS lab's second ODoH target and its relay (scripts/dnslab, W8): Cloudflare's odoh-server-go at a pinned
# commit (its git hash checked here; its modules by go.sum and Go's checksum database), with lab.patch, which
# sends its queries to the lab's backend named in DNSLAB_NAMESERVER instead of public resolvers. Built in the
# official Go image and run in the official Alpine image, both pinned by digest. One program serves both roles:
# a target at /dns-query and /.well-known/odohconfigs, a relay at /proxy?targethost=..&targetpath=..
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG COMMIT=5a9bf1f5b7b3f676558e8a4e50f94abd032ceb4a
RUN git clone --quiet https://github.com/cloudflare/odoh-server-go.git /src && cd /src && \
    git checkout --quiet --detach "$COMMIT" && test "$(git rev-parse HEAD)" = "$COMMIT"
COPY lab.patch /src/
RUN cd /src && git apply lab.patch && \
    CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod go build -trimpath -o /usr/local/bin/odoh-server .

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=build /usr/local/bin/odoh-server /usr/local/bin/odoh-server
ENTRYPOINT ["odoh-server"]
