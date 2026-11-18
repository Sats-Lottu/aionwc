"""Test-only BOLT11 invoices signed with a public test key and nonce."""

import hashlib

import pytest

from aionwc._bolt11 import BECH32_CHARSET, _hrp_expand, _polymod
from aionwc._secp256k1 import GENERATOR, ORDER


def _int_words(value, count):
    return [(value >> (5 * shift)) & 31 for shift in reversed(range(count))]


def _byte_words(value):
    count = (len(value) * 8 + 4) // 5
    padded = int.from_bytes(value, "big") << (count * 5 - len(value) * 8)
    return _int_words(padded, count)


@pytest.fixture
def invoice_factory():
    def build(hrp, fields, *, timestamp=1_700_000_000, signature=None, high_s=False):
        words = _int_words(timestamp, 7)
        for tag, value in fields:
            if isinstance(value, str):
                value = value.encode("utf-8")
            if isinstance(value, bytes):
                data = _byte_words(value)
            elif isinstance(value, int):
                data = _int_words(value, (value.bit_length() + 4) // 5)
            else:
                data = value
            words += [BECH32_CHARSET.index(tag), len(data) // 32, len(data) % 32, *data]
        if signature is None:
            padding = (-len(words) * 5) % 8
            packed = sum(word << (5 * index) for index, word in enumerate(reversed(words))) << padding
            unsigned = packed.to_bytes((len(words) * 5 + 7) // 8, "big")
            message = int.from_bytes(hashlib.sha256(hrp.encode("ascii") + unsigned).digest(), "big")
            # The test private key and nonce are both 1. These mock invoices
            # have no spending authority. Production invoice issuance uses NWC.
            r = GENERATOR[0]
            s = (message + r) % ORDER
            recovery_id = GENERATOR[1] & 1
            if (s > ORDER // 2) != high_s:
                s = ORDER - s
                recovery_id ^= 1
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recovery_id])
        words += _byte_words(signature)
        checksum = _polymod(_hrp_expand(hrp) + words + [0] * 6) ^ 1
        return hrp + "1" + "".join(BECH32_CHARSET[word] for word in words + _int_words(checksum, 6))

    return build
