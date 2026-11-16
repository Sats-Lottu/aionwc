Encryption and compatibility
============================

Nostr Wallet Connect encrypts request and response payloads. The client
verifies the wallet's signed response and matches it to the published request
before decrypting it.

Encryption modes
----------------

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Mode
     - Behavior
   * - ``auto``
     - The default. Prefers NIP-44 v2 when the wallet advertises it. Uses
       NIP-04 when the wallet advertises NIP-04, omits its encryption tag,
       or the client receives no valid wallet information event.
   * - ``nip44_v2``
     - Requires NIP-44 v2. Choose it for a wallet known to support that mode.
   * - ``nip04``
     - Uses legacy AES-256-CBC with OpenSSL's ``libcrypto`` or the optional
       ``pyaes`` fallback.

Set the mode when constructing the client.

.. code-block:: python

   wallet = NWCClient(uri, encryption="nip44_v2")

Install the NIP-04 fallback
---------------------------

If OpenSSL AES-256-CBC is unavailable, the ``nip04-fallback`` extra
provides ``pyaes``. For a release published on PyPI, choose the command
for your package manager.

.. code-block:: console
   :caption: pip

   python -m pip install "aionwc[nip04-fallback]"

.. code-block:: console
   :caption: Poetry

   poetry add "aionwc[nip04-fallback]"

.. code-block:: console
   :caption: uv

   uv add "aionwc[nip04-fallback]"

NIP-44 works independently of AES.

secp256k1 backends
------------------

The client prefers the system's ``libsecp256k1`` with ECDH, extrakeys, and
Schnorr support. OpenSSL is the next choice for the curve operations.
Without either library the client uses Python curve arithmetic, whose
execution time can vary with the inputs.

On Windows, the client searches for ``secp256k1.dll`` and
``libsecp256k1.dll`` on the system search path. It can use the
OpenSSL DLL bundled with CPython.
