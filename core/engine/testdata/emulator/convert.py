#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the KeyDescription extension of each emulator chain's leaf, for attestation.rs's tests.

    core/engine/testdata/emulator/convert.py > core/engine/testdata/emulator/vectors.tsv

It reads the .pem files in this directory, whose SHA-256 sums SOURCE records, with the DER walker of
../keyattestation/convert.py, so that the parser's reading is not shared.
"""
import importlib.util
import pathlib
import sys

sys.dont_write_bytecode = True  # Leave nothing beside the corpus's converter.
HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("corpus", HERE.parent / "keyattestation" / "convert.py")
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


def main():
    print("# SPDX-License-Identifier: CC0-1.0")
    print("# path, then its leaf's KeyDescription extension (hex); converted by convert.py")
    for path in sorted(HERE.glob("*.pem")):
        print(f"{path.name}\t{corpus.extension(corpus.leaf(path)).hex()}")


if __name__ == "__main__":
    main()
