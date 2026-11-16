# aionwc

`aionwc` is an asyncio client for Lightning wallets that expose
[Nostr Wallet Connect (NIP-47)](https://github.com/nostr-protocol/nips/blob/master/47.md).
It requires Python 3.11 or later and a wallet-generated
`nostr+walletconnect://` URI. The URI contains a private key. Store it as a
secret and keep it out of logs and source control.

The package depends on `websockets` for async relay transport. For legacy
NIP-04, it uses AES-256-CBC from OpenSSL's `libcrypto`. Install the
`nip04-fallback` extra to provide `pyaes` on systems where OpenSSL AES
is unavailable. NIP-44 works independently of both AES backends.

For secp256k1, the client prefers the system's `libsecp256k1` with ECDH,
extrakeys and Schnorr support. The next choice is OpenSSL's `libcrypto`,
which performs the curve operations in ECDH and the Python BIP340
implementation. The client can fall back to Python curve arithmetic when
neither shared library is available. The Python arithmetic uses variable
execution time. On Windows, the client looks for `secp256k1.dll` or
`libsecp256k1.dll` on the system search path and can use the OpenSSL DLL
bundled with CPython.

To install a local build, run `poetry build` followed by
`pip install dist/aionwc-0.1.0-py3-none-any.whl`. To include the fallback,
use `pip install "dist/aionwc-0.1.0-py3-none-any.whl[nip04-fallback]"`.

## Documentation

The [documentation source](https://github.com/Sats-Lottu/aionwc/tree/main/docs) includes a quickstart, wallet
operations, encryption compatibility, and a generated API reference.
The [development guide](https://github.com/Sats-Lottu/aionwc/blob/main/docs/development.rst) covers publishing it on
Read the Docs Community.

```console
poetry install --with docs
poetry run sphinx-build -M html docs docs/_build -W --keep-going
```

Open `docs/_build/html/index.html` to preview the generated site.

## Usage

```python
import asyncio
import os

from aionwc import NWCClient


async def main():
    wallet = NWCClient(os.environ["NWC_URI"])
    info, balance_msat = await asyncio.gather(
        wallet.get_info(),
        wallet.get_balance(),
    )
    print(info.get("alias"), balance_msat)


asyncio.run(main())
```

- `get_info()` returns wallet metadata and the available methods.
- `get_balance()` returns the balance as an integer in millisatoshis.
- `make_invoice(amount_msat, description="...")` creates a BOLT11 invoice.
- `pay_invoice(invoice)` pays a BOLT11 invoice and returns the wallet's confirmation.
- `lookup_invoice(payment_hash=...)` or `lookup_invoice(invoice=...)` returns invoice details.
- `list_transactions(transaction_type="incoming", limit=10)` returns a list of transactions.
- `request(method, params)` calls an additional method supported by the wallet.

Invoice and payment methods return the wallet's result dictionary. Each call
opens and closes its own WebSocket. The default timeout is 30 seconds for the
entire call. The client prefers NIP-44 v2 when the wallet advertises it and
uses NIP-04 when it receives no valid wallet information event or the event
has no encryption tag. To require NIP-44, set
`NWCClient(uri, encryption="nip44_v2")`.

`NWCWalletError` exposes the wallet's `code` and `message`.
`NWCRelayError` and its subclass `NWCTimeoutError` can carry the signed
`request_id` if publication was attempted. Requests can move to another relay
before publication. If a payment times out or the connection drops after
publication, check its state with `lookup_invoice` before attempting it again.

## Development

```console
poetry install --extras nip04-fallback
poetry run pytest --cov=aionwc --cov-report=term-missing
poetry check --lock
poetry build
poetry run twine check --strict dist/*
```

To run the integration test, start Docker and install the integration
dependency group. Testcontainers starts LNbits and a local Nostr relay with
fresh test wallets and LNbits' `FakeWallet` funding source. The setup pulls
container images and downloads the LNbits NWC Provider extension on first use.

```console
poetry install --with integration
poetry run pytest -m integration
```

The [release guide](https://github.com/Sats-Lottu/aionwc/blob/main/.github/RELEASING.md)
covers Trusted Publishing and how to validate and publish distributions to PyPI.

## Credits

`aionwc` is maintained by Sats-Lottu and inspired by eddieoz's
[nwc-agent](https://github.com/eddieoz/nwc-agent). Portions adapted from
`nwc-agent` retain their MIT attribution in the license.

