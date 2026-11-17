#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Writes the synthetic attestation chains that AttestationChainTest uses where Google's real chains cannot
# show a rule: dates in odd places, shapes no phone makes, a root that does not sign itself. Each chain is
# leaf first and its leaf carries the KeyDescription of core/engine/testdata/attestation/tee.der; the root's
# key is the one the tests trust. Run from anywhere; it needs OpenSSL 3.4 or later, and the keys it makes
# are thrown away, so each run writes new certificates.
#
#   android/app/src/test/resources/attestation/synthetic/generate.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT=$(git rev-parse --show-toplevel)
work=$(mktemp -d "${TMPDIR:-/tmp}/attestation-chains.XXXXXX")
trap 'rm -rf "$work"' EXIT

# The KeyDescription, without the OCTET STRING that getExtensionValue wraps it in (04 81 e4).
description=$(od -An -v -tx1 "$ROOT/core/engine/testdata/attestation/tee.der" | tr -d ' \n' | cut -c7-)
printf 'keyUsage=critical,digitalSignature\n1.3.6.1.4.1.11129.2.1.17=DER:%s\n' "$description" > "$work/leaf.ext"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' > "$work/ca.ext"

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$1.key" 2>/dev/null; }

# cert NAME SUBJECT ISSUER|self EXTFILE NOT-BEFORE NOT-AFTER: a new key and its certificate, issued by the
# certificate ISSUER (and its key), or by itself.
cert() {
    local name=$1 subject=$2 issuer=$3 ext=$4 from=$5 until=$6
    key "$name"
    openssl req -new -key "$work/$name.key" -subj "$subject" -out "$work/$name.csr"
    if [ "$issuer" = self ]; then
        openssl x509 -req -in "$work/$name.csr" -signkey "$work/$name.key" -extfile "$work/$ext" \
            -not_before "$from" -not_after "$until" -set_serial "0x$(openssl rand -hex 8)" -out "$work/$name.pem" 2>/dev/null
    else
        openssl x509 -req -in "$work/$name.csr" -CA "$work/$issuer.pem" -CAkey "$work/$issuer.key" -extfile "$work/$ext" \
            -not_before "$from" -not_after "$until" -set_serial "0x$(openssl rand -hex 8)" -out "$work/$name.pem" 2>/dev/null
    fi
}

FROM=20200101000000Z
UNTIL=20400101000000Z

# chain FILE NAME... : the named certificates, leaf first, into FILE.
chain() { local file=$1; shift; for n in "$@"; do cat "$work/$n.pem"; done > "$file"; }

# A software keystore's shape, three certificates, whose leaf becomes valid only in 2030: the leaf's dates
# are set on the phone, and are not checked.
cert root-a "/CN=Synthetic Root A" self ca.ext $FROM $UNTIL
cert attest-a "/CN=Synthetic Attestation A" root-a ca.ext $FROM $UNTIL
cert leaf-a "/CN=Android Keystore Key" attest-a leaf.ext 20300101000000Z $UNTIL
chain leaf-not-yet-valid.pem leaf-a attest-a root-a

# The same shape under a root that expired in 2025: the root's dates are not checked either.
cert root-b "/CN=Synthetic Root B" self ca.ext 20100101000000Z 20250101000000Z
cert attest-b "/CN=Synthetic Attestation B" root-b ca.ext $FROM $UNTIL
cert leaf-b "/CN=Android Keystore Key" attest-b leaf.ext $FROM $UNTIL
chain root-expired.pem leaf-b attest-b root-b

# Its attestation certificate expired in 2025: only a factory-provisioned chain is exempt, not this one.
cert root-c "/CN=Synthetic Root C" self ca.ext $FROM $UNTIL
cert attest-c "/CN=Synthetic Attestation C" root-c ca.ext $FROM 20250101000000Z
cert leaf-c "/CN=Android Keystore Key" attest-c leaf.ext $FROM $UNTIL
chain intermediate-expired.pem leaf-c attest-c root-c

# Five certificates without Remote Key Provisioning's intermediate: no provisioning makes this shape. The
# certificate below the root is named "Droid CA2" but not of "Google LLC", which Remote Key Provisioning's is.
cert root-d "/CN=Synthetic Root D" self ca.ext $FROM $UNTIL
cert ca2-d "/O=Synthetic LLC/CN=Droid CA2" root-d ca.ext $FROM $UNTIL
cert ca3-d "/O=Synthetic LLC/CN=Droid CA3" ca2-d ca.ext $FROM $UNTIL
cert attest-d "/CN=Synthetic Attestation D" ca3-d ca.ext $FROM $UNTIL
cert leaf-d "/CN=Android Keystore Key" attest-d leaf.ext $FROM $UNTIL
chain five-not-remote.pem leaf-d attest-d ca3-d ca2-d root-d

# A root named as its own issuer but signed by another key under the same name: not self-signed.
key other-e
openssl req -new -x509 -key "$work/other-e.key" -subj "/CN=Synthetic Root E" -days 1 -out "$work/other-e.pem"
cert root-e "/CN=Synthetic Root E" other-e ca.ext $FROM $UNTIL
# The root's own key signs the attestation certificate, so only the root's own signature is wrong.
cert attest-e "/CN=Synthetic Attestation E" root-e ca.ext $FROM $UNTIL
cert leaf-e "/CN=Android Keystore Key" attest-e leaf.ext $FROM $UNTIL
chain root-not-self-signed.pem leaf-e attest-e root-e

# A root under the name of Google's test root for unregistered devices, with a key of its own: the name tells
# the test root, since Google reissues it, and the name alone gives a forger nothing that AOSP's published
# software root does not (ADR 0040).
cert root-f "/CN=Droid Unregistered Device CA/O=Google Test LLC" self ca.ext $FROM $UNTIL
cert attest-f "/O=TEE/CN=Synthetic Attestation F" root-f ca.ext $FROM $UNTIL
cert leaf-f "/CN=Android Keystore Key" attest-f leaf.ext $FROM $UNTIL
chain test-root-name.pem leaf-f attest-f root-f

# A certificate too long for one line of the debug builds' lab record (AttestationLabTest): 3,000 bytes of an
# extension of no meaning make its base64 longer than one part.
key big
printf '1.3.6.1.4.1.99999.1=DER:04820bb8%s\n' "$(head -c 3000 /dev/zero | od -An -v -tx1 | tr -d ' \n')" > "$work/big.ext"
openssl req -new -key "$work/big.key" -subj "/CN=Synthetic Large Certificate" -out "$work/big.csr"
openssl x509 -req -in "$work/big.csr" -signkey "$work/big.key" -extfile "$work/big.ext" \
    -not_before $FROM -not_after $UNTIL -set_serial "0x$(openssl rand -hex 8)" -out large-certificate.pem 2>/dev/null
