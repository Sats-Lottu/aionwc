"""Nostr key agreement and BIP340 signatures, based on nwc-agent."""

from hashlib import sha256
from secrets import token_bytes

try:
    from ._native_secp256k1 import load_libsecp256k1, load_openssl
except ImportError:
    # Some Python builds omit the optional ctypes module.
    _LIBSECP256K1 = _OPENSSL = None
else:
    _LIBSECP256K1 = load_libsecp256k1()
    _OPENSSL = load_openssl() if _LIBSECP256K1 is None else None

FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None


def _point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD)
    slope %= FIELD
    x = (slope * slope - x1 - x2) % FIELD
    return x, (slope * (x1 - x) - y1) % FIELD


def _point_mul(scalar: int, point: Point) -> Point:
    result = None
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _lift_x(pubkey: bytes) -> tuple[int, int]:
    if len(pubkey) != 32:
        raise ValueError("Public key must be 32 bytes")
    x = int.from_bytes(pubkey, "big")
    if x >= FIELD:
        raise ValueError("Public key is outside the curve field")
    square = (pow(x, 3, FIELD) + 7) % FIELD
    y = pow(square, (FIELD + 1) // 4, FIELD)
    if pow(y, 2, FIELD) != square:
        raise ValueError("Public key is not on secp256k1")
    return x, FIELD - y if y % 2 else y


def _secret_bytes(secret: int) -> bytes:
    if not 1 <= secret < ORDER:
        raise ValueError("Private key is outside the scalar range")
    return secret.to_bytes(32, "big")


def _private_coordinates(secret: int, peer: bytes | None = None) -> tuple[bytes, int]:
    encoded = _secret_bytes(secret)
    if _OPENSSL is not None:
        coordinates = (
            _OPENSSL.multiply(generator_scalar=encoded)
            if peer is None
            else _OPENSSL.multiply(peer=peer, peer_scalar=encoded)
        )
        if coordinates is not None:
            return coordinates
    else:
        point = _point_mul(secret, GENERATOR if peer is None else _lift_x(peer))
        if point is not None:
            return point[0].to_bytes(32, "big"), point[1] & 1
    raise ValueError("Invalid curve point")


def public_key(secret: int) -> bytes:
    if _LIBSECP256K1 is not None:
        return _LIBSECP256K1.public_key(_secret_bytes(secret))
    return _private_coordinates(secret)[0]


def shared_secret(secret: int, peer: bytes) -> bytes:
    if len(peer) != 32:
        raise ValueError("Public key must be 32 bytes")
    if _LIBSECP256K1 is not None:
        return _LIBSECP256K1.shared_secret(_secret_bytes(secret), peer)
    return _private_coordinates(secret, peer)[0]


def _tagged_hash(tag: bytes, data: bytes) -> bytes:
    digest = sha256(tag).digest()
    return sha256(digest + digest + data).digest()


def _challenge(rx: bytes, pubkey: bytes, message: bytes) -> int:
    return int.from_bytes(
        _tagged_hash(b"BIP0340/challenge", rx + pubkey + message), "big"
    ) % ORDER


def schnorr_sign(secret: int, message: bytes, *, aux: bytes | None = None) -> bytes:
    aux = token_bytes(32) if aux is None else aux
    if len(aux) != 32:
        raise ValueError("Auxiliary randomness must be 32 bytes")
    if _LIBSECP256K1 is not None:
        return _LIBSECP256K1.sign(_secret_bytes(secret), message, aux)
    pubkey, parity = _private_coordinates(secret)
    normalized = ORDER - secret if parity else secret
    hidden = normalized ^ int.from_bytes(_tagged_hash(b"BIP0340/aux", aux), "big")
    nonce = int.from_bytes(
        _tagged_hash(b"BIP0340/nonce", hidden.to_bytes(32, "big") + pubkey + message), "big"
    ) % ORDER
    r, parity = _private_coordinates(nonce)
    normalized_nonce = ORDER - nonce if parity else nonce
    s = (normalized_nonce + _challenge(r, pubkey, message) * normalized) % ORDER
    return r + s.to_bytes(32, "big")


def schnorr_verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    if _LIBSECP256K1 is not None:
        return _LIBSECP256K1.verify(pubkey, message, signature)
    r = signature[:32]
    x = int.from_bytes(r, "big")
    s = int.from_bytes(signature[32:], "big")
    if x >= FIELD or s >= ORDER:
        return False
    inverse_challenge = (-_challenge(r, pubkey, message)) % ORDER
    try:
        if _OPENSSL is not None:
            return _OPENSSL.multiply(
                generator_scalar=signature[32:],
                peer=pubkey,
                peer_scalar=inverse_challenge.to_bytes(32, "big"),
            ) == (r, 0)
        point = _lift_x(pubkey)
    except ValueError:
        return False
    expected = _point_add(
        _point_mul(s, GENERATOR),
        _point_mul(inverse_challenge, point),
    )
    return expected is not None and expected[0] == x and expected[1] % 2 == 0
