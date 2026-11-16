"""Bindings to optional system implementations of secp256k1."""

import sys
from contextlib import ExitStack
from ctypes import (
    CDLL,
    CFUNCTYPE,
    Structure,
    byref,
    c_char_p,
    c_int,
    c_size_t,
    c_ubyte,
    c_uint,
    c_void_p,
    memmove,
    memset,
)
from ctypes.util import find_library
from pathlib import Path
from secrets import token_bytes
from weakref import finalize

from ._libcrypto import bind as _bind
from ._libcrypto import load_libcrypto

_CONTEXT_NONE = 1
_POINT_CONVERSION_COMPRESSED = 2
_ECDH_HASH = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p)


@_ECDH_HASH
def _copy_x(output, x, _y, _data):
    # NIP-04 and NIP-44 use the shared point's X coordinate directly.
    memmove(output, x, 32)
    return 1


class _SchnorrParameters(Structure):
    _fields_ = [
        ("magic", c_ubyte * 4),
        ("nonce_function", c_void_p),
        ("nonce_data", c_char_p),
    ]


class LibSecp256k1:
    def __init__(self, library: CDLL) -> None:
        self._keypair = _bind(
            library, "secp256k1_keypair_create", c_int, c_void_p, c_void_p, c_void_p
        )
        self._keypair_x = _bind(
            library, "secp256k1_keypair_xonly_pub", c_int, c_void_p, c_void_p, c_void_p, c_void_p
        )
        self._x_serialize = _bind(
            library, "secp256k1_xonly_pubkey_serialize", c_int, c_void_p, c_void_p, c_void_p
        )
        self._x_parse = _bind(
            library, "secp256k1_xonly_pubkey_parse", c_int, c_void_p, c_void_p, c_void_p
        )
        self._parse = _bind(
            library, "secp256k1_ec_pubkey_parse", c_int, c_void_p, c_void_p, c_void_p, c_size_t
        )
        self._ecdh = _bind(
            library, "secp256k1_ecdh", c_int, c_void_p, c_void_p, c_void_p, c_void_p,
            _ECDH_HASH, c_void_p,
        )
        self._sign = _bind(
            library, "secp256k1_schnorrsig_sign_custom", c_int,
            c_void_p, c_void_p, c_void_p, c_size_t, c_void_p, c_void_p,
        )
        self._verify = _bind(
            library, "secp256k1_schnorrsig_verify", c_int,
            c_void_p, c_void_p, c_void_p, c_size_t, c_void_p,
        )
        create = _bind(library, "secp256k1_context_create", c_void_p, c_uint)
        destroy = _bind(library, "secp256k1_context_destroy", None, c_void_p)
        randomize = _bind(library, "secp256k1_context_randomize", c_int, c_void_p, c_void_p)
        self._context = create(_CONTEXT_NONE)
        if not self._context:
            raise OSError("Cannot create libsecp256k1 context")
        cleanup = finalize(self, destroy, self._context)
        if not randomize(self._context, token_bytes(32)):
            cleanup()
            raise OSError("Cannot randomize libsecp256k1 context")

    def public_key(self, secret: bytes) -> bytes:
        keypair = (c_ubyte * 96)()
        point, output = (c_ubyte * 64)(), (c_ubyte * 32)()
        try:
            if not self._keypair(self._context, keypair, secret):
                raise ValueError("Invalid private key")
            self._keypair_x(self._context, point, None, keypair)
            self._x_serialize(self._context, output, point)
            return bytes(output)
        finally:
            memset(keypair, 0, len(keypair))

    def shared_secret(self, secret: bytes, peer: bytes) -> bytes:
        point, output = (c_ubyte * 64)(), (c_ubyte * 32)()
        encoded = b"\x02" + peer
        if not self._parse(self._context, point, encoded, len(encoded)):
            raise ValueError("Invalid public key")
        try:
            if not self._ecdh(self._context, output, point, secret, _copy_x, None):
                raise ValueError("Cannot derive shared secret")
            return bytes(output)
        finally:
            memset(output, 0, len(output))

    def sign(self, secret: bytes, message: bytes, aux: bytes) -> bytes:
        keypair, signature = (c_ubyte * 96)(), (c_ubyte * 64)()
        params = _SchnorrParameters((0xDA, 0x6F, 0xB3, 0x8C), None, aux)
        try:
            if not self._keypair(self._context, keypair, secret):
                raise ValueError("Invalid private key")
            if not self._sign(self._context, signature, message, len(message), keypair, byref(params)):
                raise ValueError("Cannot sign Schnorr message")
            return bytes(signature)
        finally:
            memset(keypair, 0, len(keypair))

    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        point = (c_ubyte * 64)()
        if not self._x_parse(self._context, point, pubkey):
            return False
        return bool(self._verify(self._context, signature, message, len(message), point))


def _allocate(stack, create, release, *args):
    handle = create(*args)
    if not handle:
        raise ValueError("Cannot allocate OpenSSL secp256k1 data")
    stack.callback(release, handle)
    return handle


class OpenSSLCurve:
    def __init__(self, library: CDLL) -> None:
        nid = _bind(library, "OBJ_txt2nid", c_int, c_char_p)
        self._curve = nid(b"secp256k1")
        self._group_new = _bind(library, "EC_GROUP_new_by_curve_name", c_void_p, c_int)
        self._group_free = _bind(library, "EC_GROUP_free", None, c_void_p)
        self._point_new = _bind(library, "EC_POINT_new", c_void_p, c_void_p)
        self._point_free = _bind(library, "EC_POINT_clear_free", None, c_void_p)
        self._bn_new = _bind(library, "BN_bin2bn", c_void_p, c_void_p, c_int, c_void_p)
        self._bn_free = _bind(library, "BN_clear_free", None, c_void_p)
        self._ctx_new = _bind(library, "BN_CTX_new", c_void_p)
        self._ctx_free = _bind(library, "BN_CTX_free", None, c_void_p)
        self._parse = _bind(
            library, "EC_POINT_oct2point", c_int, c_void_p, c_void_p, c_void_p, c_size_t, c_void_p,
        )
        self._mul = _bind(
            library, "EC_POINT_mul", c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p,
            c_void_p,
        )
        self._serialize = _bind(
            library, "EC_POINT_point2oct", c_size_t, c_void_p, c_void_p, c_int,
            c_void_p, c_size_t, c_void_p,
        )
        # A system libcrypto may have been built without this curve.
        if not self._curve or self.multiply(generator_scalar=(1).to_bytes(32, "big")) is None:
            raise ValueError("OpenSSL does not provide secp256k1")

    def multiply(
        self,
        *,
        generator_scalar: bytes | None = None,
        peer: bytes | None = None,
        peer_scalar: bytes | None = None,
    ) -> tuple[bytes, int] | None:
        """Return the X coordinate and Y parity for s*G + t*P."""
        with ExitStack() as stack:
            group = _allocate(stack, self._group_new, self._group_free, self._curve)
            context = _allocate(stack, self._ctx_new, self._ctx_free)
            result = _allocate(stack, self._point_new, self._point_free, group)
            base = scalar = point = None
            if generator_scalar is not None:
                base = _allocate(
                    stack, self._bn_new, self._bn_free, generator_scalar, len(generator_scalar), None
                )
            if peer is not None:
                if peer_scalar is None:
                    raise ValueError("Missing OpenSSL peer scalar")
                point = _allocate(stack, self._point_new, self._point_free, group)
                encoded = b"\x02" + peer
                if not self._parse(group, point, encoded, len(encoded), context):
                    raise ValueError("Invalid public key")
                scalar = _allocate(
                    stack, self._bn_new, self._bn_free, peer_scalar, len(peer_scalar), None
                )
            if not self._mul(group, result, base, point, scalar, context):
                raise ValueError("OpenSSL secp256k1 multiplication failed")
            output = (c_ubyte * 33)()
            try:
                size = self._serialize(
                    group, result, _POINT_CONVERSION_COMPRESSED, output, len(output), context
                )
                if size == 1 and output[0] == 0:
                    return None
                if size != 33:
                    raise ValueError("Cannot serialize OpenSSL secp256k1 point")
                return bytes(output)[1:], output[0] & 1
            finally:
                memset(output, 0, len(output))


def load_libsecp256k1() -> LibSecp256k1 | None:
    paths = [find_library("secp256k1")]
    if sys.platform == "win32":
        paths.append(find_library("libsecp256k1"))
    if sys.platform == "darwin":
        paths.append("/opt/homebrew/lib/libsecp256k1.dylib")
    for path in paths:
        if not path or (sys.platform == "win32" and not Path(path).is_absolute()):
            continue
        try:
            return LibSecp256k1(CDLL(path))
        except (OSError, AttributeError):
            continue
    return None


def load_openssl() -> OpenSSLCurve | None:
    return load_libcrypto(OpenSSLCurve)
