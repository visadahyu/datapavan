"""An independent oracle for the network part's Oblivious DoH (W8, part 1): the HPKE and ODoH of RFC 9180 and RFC 9230
written again in Python over `cryptography`'s X25519 and AES-GCM, after the research's probe (odoh_probe.py, of the project's
research of 2026-11-20), with HPKE's DeriveKeyPair added so that every key comes from fixed material. RFC 9230 has
no test vectors; this writes oracle.txt, which core/net/src/odoh.rs's tests read: a target's configurations, a query
sealed to it under a fixed ephemeral key, and the target's answer sealed under a fixed nonce. The engine must seal
the same bytes from the same material, and open the answer to the same message.

    python3 -I core/net/testdata/odoh/oracle.py > core/net/testdata/odoh/oracle.txt
"""
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM, KDF, AEAD = 0x0020, 0x0001, 0x0001
SUITE_KEM = b"KEM" + struct.pack(">H", KEM)
SUITE = b"HPKE" + struct.pack(">HHH", KEM, KDF, AEAD)


def extract(salt, ikm):
    return hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()


def expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def lext(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def lexp(suite, prk, label, info, length):
    return expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def derive_keypair(ikm):
    """RFC 9180 7.1.3, DeriveKeyPair for X25519."""
    dkp = lext(SUITE_KEM, b"", b"dkp_prk", ikm)
    sk = lexp(SUITE_KEM, dkp, b"sk", b"", 32)
    private = X25519PrivateKey.from_private_bytes(sk)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def lp(b):
    return struct.pack(">H", len(b)) + b


def setup_base_s(ikm_e, pk_r, info):
    sk_e, pk_e = derive_keypair(ikm_e)
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    eae = lext(SUITE_KEM, b"", b"eae_prk", dh)
    shared = lexp(SUITE_KEM, eae, b"shared_secret", pk_e + pk_r, 32)
    context = b"\x00" + lext(SUITE, b"", b"psk_id_hash", b"") + lext(SUITE, b"", b"info_hash", info)
    secret = lext(SUITE, shared, b"secret", b"")
    key = lexp(SUITE, secret, b"key", context, 16)
    nonce = lexp(SUITE, secret, b"base_nonce", context, 12)
    exporter = lexp(SUITE, secret, b"exp", context, 32)
    return pk_e, key, nonce, exporter


def main():
    _, pk_r = derive_keypair(b"\x01" * 32)
    contents = struct.pack(">HHHH", KEM, KDF, AEAD, len(pk_r)) + pk_r
    configs = lp(struct.pack(">HH", 1, len(contents)) + contents)
    key_id = expand(extract(b"", contents), b"odoh key id", 32)
    # A query for www.example.com A with ID 0, and no padding of ODoH's own.
    message = bytes.fromhex("000001000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    plain = lp(message) + lp(b"")
    pk_e, key, nonce, exporter = setup_base_s(b"\x02" * 32, pk_r, b"odoh query")
    aad = b"\x01" + lp(key_id)
    sealed = AESGCM(key).encrypt(nonce, plain, aad)
    query = b"\x01" + lp(key_id) + lp(pk_e + sealed)
    # The target's answer, under the response nonce 0x03 * 16.
    answer = bytes.fromhex("000081800001000100000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01" \
        + bytes.fromhex("c00c000100010000003c00045db8d822")
    response_nonce = b"\x03" * 16
    response_secret = lexp(SUITE, exporter, b"sec", b"odoh response", 16)
    prk = extract(plain + lp(response_nonce), response_secret)
    response_key = expand(prk, b"odoh key", 16)
    response_iv = expand(prk, b"odoh nonce", 12)
    sealed_answer = AESGCM(response_key).encrypt(response_iv, lp(answer) + lp(b""), b"\x02" + lp(response_nonce))
    response = b"\x02" + lp(response_nonce) + lp(sealed_answer)
    print("configs", configs.hex())
    print("ikm-e", ("02" * 32))
    print("message", message.hex())
    print("query", query.hex())
    print("answer", answer.hex())
    print("response", response.hex())


if __name__ == "__main__":
    main()
