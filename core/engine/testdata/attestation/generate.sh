#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Encodes the attestation test vectors with OpenSSL's ASN1_generate_nconf, from configurations written
# from the published schema, so that attestation.rs's tests read bytes from an encoder that shares no
# code with their own (whose output they compare with tee.der):
#
#   core/engine/testdata/attestation/generate.sh
#
# OpenSSL writes DER. The vectors are the project's own, under the project's licence.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
for name in tee software; do
    openssl asn1parse -genconf "$name.cnf" -out "$name.der" -noout
done
