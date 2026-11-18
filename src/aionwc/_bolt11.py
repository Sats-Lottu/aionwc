"""BOLT11 decoding adapted from eddieoz's MIT-licensed nwc-agent/scripts/nwc_bolt11.py.

Amounts use integral millisatoshis. Tagged fields and ECDSA signatures are
validated before their contents are used by HTTP payment protocols.
"""

import re
from dataclasses import dataclass
from hashlib import sha256

from ._secp256k1 import ecdsa_payee

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_MAP = {char: index for index, char in enumerate(BECH32_CHARSET)}
_POLYMOD_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_FIXED_LENGTHS = {"p": 52, "s": 52, "h": 52, "n": 53}
_SINGLE_FIELDS = frozenset("psdhnxc9")
# BOLT 9 invoice features, including the assumed onion and payment-secret bits
# used in older invoices. The wallet performs the actual Lightning routing.
_KNOWN_REQUIRED_FEATURES = {8, 14, 16, 24, 36, 48}


@dataclass(frozen=True)
class Invoice:
    currency: str
    amount_msat: int | None
    date: int
    payment_hash: str
    payment_secret: str
    description: str | None
    description_hash: str | None
    payee: str
    expiry: int

    @property
    def expiry_time(self) -> int:
        return self.date + self.expiry


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        high = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(_POLYMOD_GEN):
            if (high >> bit) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [value >> 5 for value in hrp.encode()] + [0] + [value & 31 for value in hrp.encode()]


def _decode_bech32(value: str) -> tuple[str, list[int]]:
    if (not value or len(value) > 8192 or not value.isascii()
            or value != value.lower() and value != value.upper()):
        raise ValueError("Invalid BOLT11 Bech32 string")
    value = value.lower()
    separator = value.rfind("1")
    if separator < 1 or separator + 7 > len(value):
        raise ValueError("Missing BOLT11 Bech32 separator or checksum")
    hrp = value[:separator]
    try:
        words = [_CHARSET_MAP[char] for char in value[separator + 1:]]
    except KeyError:
        raise ValueError("Invalid BOLT11 Bech32 character") from None
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise ValueError("Invalid BOLT11 Bech32 checksum")
    return hrp, words[:-6]


def _parse_amount_from_hrp(hrp: str) -> tuple[str, int | None]:
    match = re.fullmatch(r"ln(bcrt|bc|tbs|tb)(?:([0-9]{1,19})([munp]?))?", hrp)
    if match is None:
        raise ValueError("Invalid BOLT11 currency or amount")
    currency, digits, multiplier = match.groups()
    if digits is None:
        return currency, None
    amount = int(digits)
    if amount <= 0:
        raise ValueError("BOLT11 amount must be positive")
    if multiplier == "p":
        if amount % 10:
            raise ValueError("BOLT11 amount has sub-millisatoshi precision")
        return currency, amount // 10
    return currency, amount * {"": 100_000_000_000, "m": 100_000_000, "u": 100_000, "n": 100}[multiplier]


def _words_to_int(words: list[int]) -> int:
    value = 0
    for word in words:
        value = (value << 5) | word
    return value


def _words_to_bytes(words: list[int], *, pad: bool = False) -> bytes:
    accumulator = 0
    bits = 0
    result = bytearray()
    for word in words:
        accumulator = ((accumulator << 5) | word) & 0xFFF
        bits += 5
        if bits >= 8:
            bits -= 8
            result.append((accumulator >> bits) & 0xFF)
    remainder = (accumulator << (8 - bits)) & 0xFF
    if pad and bits:
        result.append(remainder)
    elif not pad and (bits >= 5 or remainder):
        raise ValueError("Invalid BOLT11 field padding")
    return bytes(result)


def _decode_tagged_fields(words: list[int]) -> dict[str, list[int]]:
    fields = {}
    position = 0
    while position < len(words):
        if position + 3 > len(words):
            raise ValueError("Truncated BOLT11 field header")
        tag = BECH32_CHARSET[words[position]]
        length = words[position + 1] * 32 + words[position + 2]
        position += 3
        end = position + length
        if end > len(words):
            raise ValueError("Truncated BOLT11 field")
        if tag in _FIXED_LENGTHS and length != _FIXED_LENGTHS[tag]:
            raise ValueError("Invalid fixed-length BOLT11 field")
        if tag in _SINGLE_FIELDS:
            if tag in fields:
                raise ValueError("Repeated BOLT11 field")
            fields[tag] = words[position:end]
        position = end
    if "p" not in fields or "s" not in fields:
        raise ValueError("Missing BOLT11 payment hash or secret")
    if ("d" in fields) == ("h" in fields):
        raise ValueError("BOLT11 needs exactly one description or description hash")
    return fields


def parse_invoice(value: str) -> Invoice:
    """Decode BOLT11 data and verify its signing key, including expired invoices."""
    hrp, words = _decode_bech32(value)
    currency, amount_msat = _parse_amount_from_hrp(hrp)
    if len(words) < 111:
        raise ValueError("BOLT11 timestamp or signature is missing")
    fields = _decode_tagged_fields(words[7:-104])
    features = _words_to_int(fields.get("9", []))
    required = {bit for bit in range(0, features.bit_length(), 2) if features >> bit & 1}
    if required - _KNOWN_REQUIRED_FEATURES:
        raise ValueError("Unknown required BOLT11 feature")
    signature = _words_to_bytes(words[-104:])
    message = sha256(hrp.encode("ascii") + _words_to_bytes(words[:-104], pad=True)).digest()
    pubkey = _words_to_bytes(fields["n"]) if "n" in fields else None
    payee = ecdsa_payee(message, signature, pubkey).hex()
    description = _words_to_bytes(fields["d"]).decode("utf-8") if "d" in fields else None
    description_hash = _words_to_bytes(fields["h"]).hex() if "h" in fields else None
    return Invoice(
        currency=currency, amount_msat=amount_msat, date=_words_to_int(words[:7]),
        payment_hash=_words_to_bytes(fields["p"]).hex(),
        payment_secret=_words_to_bytes(fields["s"]).hex(), description=description,
        description_hash=description_hash, payee=payee,
        expiry=_words_to_int(fields["x"]) if "x" in fields else 3600,
    )
