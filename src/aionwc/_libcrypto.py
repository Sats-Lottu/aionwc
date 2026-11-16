"""Discovery and bindings for the system OpenSSL shared library."""

import sys
from collections.abc import Callable, Iterator
from ctypes import CDLL, POINTER, byref, c_int, c_ubyte, c_void_p, memset, string_at
from ctypes.util import find_library
from pathlib import Path
from typing import TypeVar

AES_BLOCK_SIZE = 16
Backend = TypeVar("Backend")


def bind(library, name, restype, *argtypes):
    function = getattr(library, name)
    function.restype = restype
    function.argtypes = argtypes
    return function


def _libcrypto_paths() -> Iterator[str | Path]:
    if sys.platform == "win32":
        for version in ("4", "3"):
            for suffix in ("-x64", "-arm64", ""):
                name = f"libcrypto-{version}{suffix}"
                if (path := find_library(name)) and Path(path).is_absolute():
                    yield path
                bundled = Path(sys.base_prefix) / "DLLs" / f"{name}.dll"
                if bundled.is_file():
                    yield bundled
    elif path := find_library("crypto"):
        yield path


def load_libcrypto(create_backend: Callable[[CDLL], Backend]) -> Backend | None:
    for path in _libcrypto_paths():
        try:
            return create_backend(CDLL(str(path)))
        except (OSError, AttributeError, ValueError):
            continue
    return None


class OpenSSLAES256CBC:
    """AES-256-CBC with OpenSSL's standard PKCS#7 padding."""

    def __init__(self, library: CDLL) -> None:
        self._create = bind(library, "EVP_CIPHER_CTX_new", c_void_p)
        self._free = bind(library, "EVP_CIPHER_CTX_free", None, c_void_p)
        self._init = bind(
            library, "EVP_CipherInit_ex", c_int,
            c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_int,
        )
        self._update = bind(
            library, "EVP_CipherUpdate", c_int,
            c_void_p, c_void_p, POINTER(c_int), c_void_p, c_int,
        )
        self._final = bind(library, "EVP_CipherFinal_ex", c_int, c_void_p, c_void_p, POINTER(c_int))
        self._cipher = bind(library, "EVP_aes_256_cbc", c_void_p)()
        if not self._cipher:
            raise ValueError("OpenSSL does not provide AES-256-CBC")
        # OpenSSL can expose this cipher while the active providers cannot initialize it.
        self.crypt(bytes(32), bytes(AES_BLOCK_SIZE), b"", encrypt=True)

    def crypt(self, key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
        if len(key) != 32 or len(iv) != AES_BLOCK_SIZE:
            raise ValueError("Invalid AES-256-CBC key or IV length")
        if len(data) > (1 << 31) - 1 - AES_BLOCK_SIZE:
            raise ValueError("AES-256-CBC input exceeds the EVP length limit")
        output = (c_ubyte * (len(data) + 2 * AES_BLOCK_SIZE))()
        written, final_size = c_int(), c_int()
        context = self._create()
        if not context:
            raise ValueError("Cannot allocate OpenSSL cipher context")
        try:
            if not self._init(context, self._cipher, None, key, iv, encrypt):
                raise ValueError("Cannot initialize AES-256-CBC")
            if not self._update(context, output, byref(written), data, len(data)):
                raise ValueError("Cannot process AES-256-CBC data")
            if not self._final(context, byref(output, written.value), byref(final_size)):
                raise ValueError("Cannot finalize AES-256-CBC data")
            return string_at(output, written.value + final_size.value)
        finally:
            self._free(context)
            memset(output, 0, len(output))
