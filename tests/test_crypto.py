import hashlib
import sys
from base64 import b64decode, b64encode

import pytest

from aionwc import NWCProtocolError, _encryption, _secp256k1
from aionwc._encryption import nip44_decrypt, nip44_encrypt
from aionwc._secp256k1 import public_key, schnorr_sign, schnorr_verify, shared_secret


@pytest.fixture(params=[False, True], ids=["automatic", "python-fallback"])
def curve_backend(request, monkeypatch):
    if request.param:
        monkeypatch.setattr(_secp256k1, "_LIBSECP256K1", None)
        monkeypatch.setattr(_secp256k1, "_OPENSSL", None)


def test_bip340_reference_vector(curve_backend):
    # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    pubkey = bytes.fromhex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
    signature = bytes.fromhex(
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
        "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
    )
    assert public_key(3) == pubkey
    assert schnorr_sign(3, bytes(32), aux=bytes(32)) == signature
    assert schnorr_verify(pubkey, bytes(32), signature)
    assert not schnorr_verify(pubkey, b"\x01" + bytes(31), signature)


@pytest.mark.parametrize("backend", ["openssl", "pyaes"])
def test_nip04_aes_reference_vector_and_padding(backend, monkeypatch):
    if backend == "openssl":
        if _encryption._OPENSSL_AES is None:
            pytest.skip("OpenSSL AES-256-CBC is unavailable")
        monkeypatch.setitem(sys.modules, "pyaes", None)
    else:
        pytest.importorskip("pyaes")
        monkeypatch.setattr(_encryption, "_OPENSSL_AES", None)

    # NIST SP 800-38A F.2.5 AES-256-CBC, first block.
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ciphertext = _encryption._aes_cbc(key, iv, plaintext, encrypt=True)
    assert len(ciphertext) == 32
    assert ciphertext[:16] == bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
    assert _encryption._aes_cbc(key, iv, ciphertext, encrypt=False) == plaintext

    tampered = bytearray(ciphertext)
    tampered[15] ^= 1
    with pytest.raises(ValueError):
        _encryption._aes_cbc(key, iv, bytes(tampered), encrypt=False)

    for plaintext in ("", "fatura de teste ☕"):
        payload = _encryption.nip04_encrypt(key, plaintext)
        assert _encryption.nip04_decrypt(key, payload) == plaintext


def test_missing_nip04_backends_leave_nip44_available(monkeypatch):
    monkeypatch.setattr(_encryption, "_OPENSSL_AES", None)
    monkeypatch.setitem(sys.modules, "pyaes", None)
    key = bytes(32)
    with pytest.raises(NWCProtocolError, match="nip04-fallback"):
        _encryption.nip04_encrypt(key, "test")
    assert nip44_decrypt(key, nip44_encrypt(key, "test")) == "test"


def test_nip44_reference_vector_and_authentication(curve_backend):
    # https://github.com/nostr-protocol/nips/blob/master/44.md#tests-and-code
    key = shared_secret(1, public_key(2))
    nonce = (1).to_bytes(32, "big")
    expected = (
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAj"
        "D35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    )
    assert nip44_encrypt(key, "a", nonce=nonce) == expected
    assert nip44_decrypt(shared_secret(2, public_key(1)), expected) == "a"

    tampered = bytearray(b64decode(expected))
    tampered[-1] ^= 1
    with pytest.raises(ValueError, match="authentication code"):
        nip44_decrypt(key, b64encode(tampered).decode())


def test_invalid_curve_inputs(curve_backend):
    with pytest.raises(ValueError, match="Private key"):
        public_key(0)
    with pytest.raises(ValueError):
        shared_secret(1, bytes(32))
    assert not schnorr_verify(bytes(31), bytes(32), bytes(64))
    assert not schnorr_verify(bytes(32), bytes(32), bytes(64))


def test_nip44_extended_length_reference_vector():
    key = shared_secret(1, public_key(2))
    plaintext = "a" * 65536
    payload = nip44_encrypt(key, plaintext, nonce=(1).to_bytes(32, "big"))
    assert hashlib.sha256(payload.encode()).hexdigest() == (
        "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"
    )
    assert nip44_decrypt(key, payload) == plaintext
