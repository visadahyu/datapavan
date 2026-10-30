#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Converts Wycheproof's Ed25519 verification vectors to the TSV that datapack.rs tests read.

    curl -sSfLO https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ed25519_test.json
    core/engine/testdata/wycheproof/convert.py ed25519_test.json > core/engine/testdata/wycheproof/ed25519.tsv

Record the file's SHA-256 and the date in SOURCE.
"""
import json
import sys

data = json.load(open(sys.argv[1]))
print("# SPDX-License-Identifier: Apache-2.0")
print("# SPDX-FileCopyrightText: Google LLC and the C2SP contributors (Project Wycheproof)")
print("# tcId, result (valid, invalid, acceptable), flags, public key, message, signature; hex")
for group in data["testGroups"]:
    key = group["publicKey"]["pk"]
    for test in group["tests"]:
        print("\t".join([str(test["tcId"]), test["result"], ",".join(test["flags"]), key, test["msg"], test["sig"]]))
