"""NIP-04 and NIP-44 v2 payload encryption, based on nwc-agent."""

import hmac
from base64 import b64decode, b64encode
from secrets import token_bytes
from struct import pack, unpack

from .errors import NWCProtocolError

try:
    from ._libcrypto import OpenSSLAES256CBC, load_libcrypto
except ImportError:
    # Some Python builds omit the optional ctypes module.
    _OPENSSL_AES = None
else:
    _OPENSSL_AES = load_libcrypto(OpenSSLAES256CBC)

AES_BLOCK_SIZE = 16
CHACHA_MASK = 0xFFFFFFFF
CHACHA_CONSTANTS = unpack("<4I", b"expand 32-byte k")
CHACHA_ROUND = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
)


def _aes_cbc(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    if len(key) != 32:
        raise ValueError("NIP-04 requires a 32-byte AES key")
    if _OPENSSL_AES is not None:
        return _OPENSSL_AES.crypt(key, iv, data, encrypt=encrypt)

    try:
        from pyaes import AESModeOfOperationCBC
    except ImportError:
        raise NWCProtocolError(
            "NIP-04 requires OpenSSL AES-256-CBC or the aionwc[nip04-fallback] extra"
        ) from None

    aes = AESModeOfOperationCBC(key, iv)
    if encrypt:
        padding = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        data += bytes([padding]) * padding
    crypt_block = aes.encrypt if encrypt else aes.decrypt
    result = b"".join(
        crypt_block(data[offset:offset + AES_BLOCK_SIZE])
        for offset in range(0, len(data), AES_BLOCK_SIZE)
    )
    if encrypt:
        return result
    padding = result[-1]
    if not 1 <= padding <= AES_BLOCK_SIZE or result[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid NIP-04 padding")
    return result[:-padding]


def nip04_encrypt(key: bytes, plaintext: str) -> str:
    iv = token_bytes(AES_BLOCK_SIZE)
    ciphertext = _aes_cbc(key, iv, plaintext.encode(), encrypt=True)
    return f"{b64encode(ciphertext).decode()}?iv={b64encode(iv).decode()}"


def nip04_decrypt(key: bytes, payload: str) -> str:
    encoded, separator, encoded_iv = payload.partition("?iv=")
    if not separator:
        raise ValueError("Missing NIP-04 initialization vector")
    ciphertext = b64decode(encoded, validate=True)
    iv = b64decode(encoded_iv, validate=True)
    if len(iv) != AES_BLOCK_SIZE or not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("Invalid NIP-04 payload length")
    return _aes_cbc(key, iv, ciphertext, encrypt=False).decode()


def _rotate(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & CHACHA_MASK


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & CHACHA_MASK
    state[d] = _rotate(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & CHACHA_MASK
    state[b] = _rotate(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & CHACHA_MASK
    state[d] = _rotate(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & CHACHA_MASK
    state[b] = _rotate(state[b] ^ state[c], 7)


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    key_words = unpack("<8I", key)
    nonce_words = unpack("<3I", nonce)
    result = bytearray()
    for counter, start in enumerate(range(0, len(data), 64)):
        state = (*CHACHA_CONSTANTS, *key_words, counter, *nonce_words)
        working = list(state)
        for _ in range(10):
            for indices in CHACHA_ROUND:
                _quarter_round(working, *indices)
        block = pack("<16I", *((a + b) & CHACHA_MASK for a, b in zip(working, state)))
        result.extend(a ^ b for a, b in zip(data[start:start + 64], block))
    return bytes(result)


def _message_keys(shared_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    conversation_key = hmac.digest(b"nip44-v2", shared_key, "sha256")
    blocks = []
    previous = b""
    for counter in range(1, 4):
        previous = hmac.digest(conversation_key, previous + nonce + bytes([counter]), "sha256")
        blocks.append(previous)
    keys = b"".join(blocks)
    return keys[:32], keys[32:44], keys[44:76]


def _padded_length(length: int) -> int:
    if length <= 32:
        return 32
    next_power = 1 << (length - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((length + chunk - 1) // chunk)


def nip44_encrypt(key: bytes, plaintext: str, *, nonce: bytes | None = None) -> str:
    data = plaintext.encode()
    length = len(data)
    if not 1 <= length <= 0xFFFFFFFF:
        raise ValueError("Invalid NIP-44 plaintext length")
    nonce = token_bytes(32) if nonce is None else nonce
    if len(nonce) != 32:
        raise ValueError("NIP-44 nonce must be 32 bytes")
    prefix = pack(">H", length) if length < 65536 else b"\x00\x00" + pack(">I", length)
    padded = prefix + data + bytes(_padded_length(length) - length)
    cipher_key, cipher_nonce, mac_key = _message_keys(key, nonce)
    ciphertext = _chacha20_xor(cipher_key, cipher_nonce, padded)
    mac = hmac.digest(mac_key, nonce + ciphertext, "sha256")
    return b64encode(b"\x02" + nonce + ciphertext + mac).decode()


def nip44_decrypt(key: bytes, payload: str) -> str:
    raw = b64decode(payload, validate=True)
    if len(raw) < 99 or raw[0] != 2:
        raise ValueError("Invalid NIP-44 v2 payload")
    nonce, ciphertext, mac = raw[1:33], raw[33:-32], raw[-32:]
    cipher_key, cipher_nonce, mac_key = _message_keys(key, nonce)
    if not hmac.compare_digest(mac, hmac.digest(mac_key, nonce + ciphertext, "sha256")):
        raise ValueError("Invalid NIP-44 authentication code")
    padded = _chacha20_xor(cipher_key, cipher_nonce, ciphertext)
    length = int.from_bytes(padded[:2], "big")
    prefix_size = 2
    if length == 0:
        length = int.from_bytes(padded[2:6], "big")
        prefix_size = 6
        if length < 65536:
            raise ValueError("Invalid NIP-44 extended length")
    if len(padded) != prefix_size + _padded_length(length):
        raise ValueError("Invalid NIP-44 padding")
    return padded[prefix_size:prefix_size + length].decode()
