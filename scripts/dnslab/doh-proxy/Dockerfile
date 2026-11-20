# The DNS lab's ODoH target of odoh-rs and its plain DoH server (scripts/dnslab, W8): DNSCrypt's doh-server,
# crate doh-proxy 0.11.1 from crates.io (its sha256 checked here, every dependency's by its Cargo.lock with
# --locked), built with its TLS feature (rustls) in the official Rust image and run in the official Alpine
# image, both pinned by digest. It serves DoH and ODoH (RFC 9230) at /dns-query and its ODoH configs at
# /.well-known/odohconfigs, with a key it makes at its start.
FROM rust:1.100.0-alpine3.24@sha256:de1e0058543a81ed7b046629167db587c67a94bdf37cce14eb27f0ec83baaffb AS build
ADD --checksum=sha256:c7d1f25bda56fc4d56bd3e4bd41da4caf0d58f4032d82609d7daf5d2f224d8c4 \
    https://static.crates.io/crates/doh-proxy/doh-proxy-0.11.1.crate /src/doh-proxy-0.11.1.crate
RUN cd /src && tar xzf doh-proxy-0.11.1.crate && cd doh-proxy-0.11.1 && \
    cargo build --release --locked && cp target/release/doh-proxy /usr/local/bin/doh-proxy

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=build /usr/local/bin/doh-proxy /usr/local/bin/doh-proxy
ENTRYPOINT ["doh-proxy"]
