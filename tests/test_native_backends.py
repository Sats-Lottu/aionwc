"""Exercise optional C bindings, including cleanup when native calls fail."""

import ctypes
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aionwc import _libcrypto as crypto
from aionwc import _native_secp256k1 as native


def library(*names):
    return SimpleNamespace(**{name: Mock(return_value=1) for name in names})


@pytest.fixture
def secp_library():
    return library(*("secp256k1_" + name for name in (
        "keypair_create", "keypair_xonly_pub", "xonly_pubkey_serialize",
        "xonly_pubkey_parse", "ec_pubkey_parse", "ecdh", "schnorrsig_sign_custom",
        "schnorrsig_verify", "context_create", "context_destroy", "context_randomize",
    )))


def test_secp_binding_buffers_parameters_and_cleanup(secp_library):
    backend = native.LibSecp256k1(secp_library)
    secret, peer, auxiliary = b"s" * 32, b"p" * 32, b"a" * 32
    keypairs, shared_outputs = [], []

    def keypair(context, output, key):
        assert context == 1 and key == secret
        ctypes.memset(output, 0xAB, len(output))
        keypairs.append(output)
        return 1

    def serialize(context, output, point):
        ctypes.memmove(output, peer, 32)
        return 1

    def ecdh(context, output, point, key, callback, data):
        assert key == secret
        shared_outputs.append(output)
        return callback(output, peer, None, data)

    def sign(context, output, message, size, pair, parameters):
        params = ctypes.cast(parameters, ctypes.POINTER(native._SchnorrParameters)).contents
        assert bytes(params.magic) == bytes.fromhex("da6fb38c")
        assert params.nonce_function is None and params.nonce_data == auxiliary
        assert message == b"message" and size == len(message)
        ctypes.memmove(output, b"z" * 64, 64)
        return 1

    secp_library.secp256k1_keypair_create.side_effect = keypair
    secp_library.secp256k1_xonly_pubkey_serialize.side_effect = serialize
    secp_library.secp256k1_ecdh.side_effect = ecdh
    secp_library.secp256k1_schnorrsig_sign_custom.side_effect = sign
    assert backend.public_key(secret) == peer
    assert backend.shared_secret(secret, peer) == peer
    assert backend.sign(secret, b"message", auxiliary) == b"z" * 64
    assert all(bytes(buffer) == bytes(len(buffer)) for buffer in keypairs + shared_outputs)
    assert backend.verify(peer, b"message", b"z" * 64)
    secp_library.secp256k1_schnorrsig_verify.return_value = 0
    assert not backend.verify(peer, b"message", b"z" * 64)
    secp_library.secp256k1_xonly_pubkey_parse.return_value = 0
    assert not backend.verify(peer, b"message", b"z" * 64)
    assert secp_library.secp256k1_schnorrsig_verify.call_count == 2
    assert secp_library.secp256k1_ec_pubkey_parse.call_args.args[2:] == (b"\x02" + peer, 33)


@pytest.mark.parametrize("call,error", [
    ("context_create", "create"), ("context_randomize", "randomize"),
])
def test_secp_context_failures_release_created_context(secp_library, call, error):
    getattr(secp_library, "secp256k1_" + call).return_value = 0
    with pytest.raises(OSError, match=error):
        native.LibSecp256k1(secp_library)
    assert secp_library.secp256k1_context_destroy.call_count == (call == "context_randomize")


@pytest.mark.parametrize("operation,failed_call,error", [
    ("public_key", "keypair_create", "Invalid private key"),
    ("shared_secret", "ec_pubkey_parse", "Invalid public key"),
    ("shared_secret", "ecdh", "derive shared secret"),
    ("sign", "keypair_create", "Invalid private key"),
    ("sign", "schnorrsig_sign_custom", "sign Schnorr"),
])
def test_secp_operation_failures(secp_library, operation, failed_call, error):
    backend = native.LibSecp256k1(secp_library)
    getattr(secp_library, "secp256k1_" + failed_call).return_value = 0
    arguments = {"public_key": (bytes(32),), "shared_secret": (bytes(32), bytes(32)),
                 "sign": (bytes(32), b"message", bytes(32))}
    with pytest.raises(ValueError, match=error):
        getattr(backend, operation)(*arguments[operation])


@pytest.fixture
def aes_library():
    return library("EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free", "EVP_CipherInit_ex",
                   "EVP_CipherUpdate", "EVP_CipherFinal_ex", "EVP_aes_256_cbc")


def test_aes_rejects_unavailable_cipher(aes_library):
    aes_library.EVP_aes_256_cbc.return_value = 0
    with pytest.raises(ValueError, match="does not provide AES"):
        crypto.OpenSSLAES256CBC(aes_library)


@pytest.mark.parametrize("call,error", [
    ("EVP_CIPHER_CTX_new", "allocate"), ("EVP_CipherInit_ex", "initialize"),
    ("EVP_CipherUpdate", "process"), ("EVP_CipherFinal_ex", "finalize"),
])
def test_aes_failure_cleans_context_and_output(aes_library, call, error):
    backend = crypto.OpenSSLAES256CBC(aes_library)
    aes_library.EVP_CIPHER_CTX_free.reset_mock()
    buffers = []

    def update(context, output, size, data, length):
        ctypes.memset(output, 0xAB, len(output))
        buffers.append(output)
        return call != "EVP_CipherUpdate"

    aes_library.EVP_CipherUpdate.side_effect = update
    getattr(aes_library, call).return_value = 0
    with pytest.raises(ValueError, match=error):
        backend.crypt(bytes(32), bytes(16), b"data", encrypt=False)
    assert aes_library.EVP_CIPHER_CTX_free.call_count == (call != "EVP_CIPHER_CTX_new")
    assert all(bytes(buffer) == bytes(len(buffer)) for buffer in buffers)


def test_aes_input_limits(aes_library):
    backend = crypto.OpenSSLAES256CBC(aes_library)
    with pytest.raises(ValueError, match="key or IV"):
        backend.crypt(bytes(31), bytes(16), b"", encrypt=True)
    with pytest.raises(ValueError, match="key or IV"):
        backend.crypt(bytes(32), bytes(15), b"", encrypt=True)
    huge_input = Mock()
    huge_input.__len__ = Mock(return_value=1 << 31)
    with pytest.raises(ValueError, match="EVP length limit"):
        backend.crypt(bytes(32), bytes(16), huge_input, encrypt=True)


@pytest.fixture
def curve_library():
    lib = library("OBJ_txt2nid", "EC_GROUP_new_by_curve_name", "EC_GROUP_free", "EC_POINT_new",
                  "EC_POINT_clear_free", "BN_bin2bn", "BN_clear_free", "BN_CTX_new", "BN_CTX_free",
                  "EC_POINT_oct2point", "EC_POINT_mul", "EC_POINT_point2oct")
    lib.EC_POINT_point2oct.return_value = 33
    return lib


def test_openssl_allocation_failure():
    release = Mock()
    with ExitStack() as stack, pytest.raises(ValueError, match="allocate"):
        native._allocate(stack, Mock(return_value=None), release)
    release.assert_not_called()


def test_openssl_unavailable_curve(curve_library):
    curve_library.OBJ_txt2nid.return_value = 0
    with pytest.raises(ValueError, match="does not provide secp256k1"):
        native.OpenSSLCurve(curve_library)
    curve_library.EC_GROUP_new_by_curve_name.assert_not_called()


@pytest.mark.parametrize("failure,error", [
    ("missing_scalar", "Missing OpenSSL peer scalar"),
    ("EC_POINT_oct2point", "Invalid public key"),
    ("EC_POINT_mul", "multiplication failed"),
    ("EC_POINT_point2oct", "Cannot serialize"),
])
def test_openssl_curve_failure_releases_allocations(curve_library, failure, error):
    backend = native.OpenSSLCurve(curve_library)
    for name in ("EC_GROUP_free", "BN_CTX_free", "EC_POINT_clear_free", "BN_clear_free"):
        getattr(curve_library, name).reset_mock()
    if failure != "missing_scalar":
        getattr(curve_library, failure).return_value = 0
    with pytest.raises(ValueError, match=error):
        backend.multiply(peer=bytes(32), peer_scalar=None if failure == "missing_scalar" else bytes(32))
    curve_library.EC_GROUP_free.assert_called_once_with(1)
    curve_library.BN_CTX_free.assert_called_once_with(1)
    assert curve_library.EC_POINT_clear_free.call_count == (1 if failure == "missing_scalar" else 2)


def test_openssl_point_at_infinity(curve_library):
    backend = native.OpenSSLCurve(curve_library)
    curve_library.EC_POINT_point2oct.return_value = 1
    assert backend.multiply(generator_scalar=bytes(32)) is None


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_libcrypto_discovery(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(crypto, "sys", SimpleNamespace(platform=platform, base_prefix=str(tmp_path)))
    dlls = tmp_path / "DLLs"
    dlls.mkdir()
    bundled = dlls / "libcrypto-3.dll"
    bundled.touch()
    absolute = str(tmp_path / "system.dll")
    monkeypatch.setattr(crypto, "find_library", lambda name: absolute if name in {"crypto", "libcrypto-4-x64"} else "relative.dll")
    assert list(crypto._libcrypto_paths()) == ([absolute, bundled] if platform == "win32" else [absolute])


def test_libcrypto_falls_back_on_load_or_backend_failure(monkeypatch):
    monkeypatch.setattr(crypto, "_libcrypto_paths", lambda: iter(["missing", "incompatible", "usable"]))
    monkeypatch.setattr(crypto, "CDLL", Mock(side_effect=[OSError(), "old", "new"]))
    factory = Mock(side_effect=[ValueError("unsupported cipher"), "backend"])
    assert crypto.load_libcrypto(factory) == "backend"
    monkeypatch.setattr(crypto, "CDLL", Mock(side_effect=AttributeError("missing symbol")))
    assert crypto.load_libcrypto(factory) is None


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_secp_library_discovery_and_fallback(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform=platform))
    path = str(tmp_path / "secp256k1.dll")
    monkeypatch.setattr(native, "find_library", lambda name: path)
    loader = Mock(side_effect=[OSError("unavailable"), "library"])
    monkeypatch.setattr(native, "CDLL", loader)
    monkeypatch.setattr(native, "LibSecp256k1", Mock(return_value="backend"))
    assert native.load_libsecp256k1() == (None if platform == "linux" else "backend")
    monkeypatch.setattr(native, "find_library", lambda name: "relative.dll" if platform == "win32" else None)
    monkeypatch.setattr(native, "CDLL", Mock(side_effect=AttributeError("missing symbol")))
    assert native.load_libsecp256k1() is None
