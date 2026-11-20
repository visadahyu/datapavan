#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Makes the DNS lab's test CA and its servers' certificates (scripts/dnslab, W8): ECDSA P-256, the CA valid for
# twenty years, each server's certificate for ten years and a month, with the names (and, for the network's
# resolver, the addresses) the lab's clients use. The keys are written beside the certificates and committed:
# they are for the lab alone and public on purpose (README). Run it again only to replace them all; the servers
# read them at their start.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 7305 -out ca.pem \
    -subj "/O=Datapavan DNS lab/CN=Datapavan DNS lab test CA (public key, tests only)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

# server NAME SAN...
server() {
    local name=$1 san=$2
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key"
    openssl req -new -key "$name.key" -subj "/O=Datapavan DNS lab/CN=$name" -out "$work/$name.csr"
    cat >"$work/$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=$san
EOF
    openssl x509 -req -in "$work/$name.csr" -CA ca.pem -CAkey ca.key -set_serial "0x$(openssl rand -hex 16)" \
        -sha256 -days 3683 -extfile "$work/$name.ext" -out "$name.pem"
}

server relay "DNS:relay.dnslab.test"
server target-a "DNS:target-a.dnslab.test"
server target-b "DNS:target-b.dnslab.test"
server doh "DNS:doh.dnslab.test"
server dot "DNS:dot.dnslab.test"
# The network's resolver, for Private DNS on "automatic": its address as the emulator sees it (10.0.2.3, which
# the emulator sends to the -dns-server 127.0.0.2 on the computer) and as the computer sees it.
server resolver "DNS:resolver.dnslab.test,IP:10.0.2.3,IP:127.0.0.2,IP:10.0.2.2,IP:127.0.0.1"
chmod 644 ./*.key ./*.pem
echo "lab certificates written in $DIR"
