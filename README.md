<h1 align="center">
  <img src="https://raw.githubusercontent.com/Sats-Lottu/aionwc/main/docs/_static/aionwc-logo.png" alt="aionwc" width="600">
</h1>

<p align="center">
  <strong>Async Lightning payments for Python.</strong><br>
  Connect a wallet over Nostr. Build applications that send and receive Bitcoin.
</p>

<p align="center">
  <a href="https://pypi.org/project/aionwc/"><img src="https://img.shields.io/pypi/v/aionwc?color=7C6AED&amp;logo=pypi&amp;logoColor=white" alt="PyPI version"></a>
  <a href="https://pypi.org/project/aionwc/"><img src="https://img.shields.io/badge/python-%3E%3D3.11-3776AB?logo=python&amp;logoColor=white" alt="Python 3.11 or later"></a>
  <a href="https://github.com/Sats-Lottu/aionwc/actions/workflows/publish.yml"><img src="https://img.shields.io/github/actions/workflow/status/Sats-Lottu/aionwc/publish.yml?label=build&amp;logo=github" alt="Build status"></a>
  <a href="https://aionwc.readthedocs.io/"><img src="https://readthedocs.org/projects/aionwc/badge/?version=latest" alt="Documentation status"></a>
  <br>
  <a href="https://github.com/Sats-Lottu/aionwc/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/aionwc?color=7C6AED" alt="MIT license"></a>
  <a href="https://aionwc.readthedocs.io/en/latest/api.html"><img src="https://img.shields.io/badge/typing-PEP%20561-7C6AED" alt="PEP 561 typed package"></a>
  <a href="https://github.com/nostr-protocol/nips/blob/master/47.md"><img src="https://img.shields.io/badge/NWC-NIP--47-7C6AED" alt="Nostr Wallet Connect, NIP-47"></a>
  <a href="#http-payments"><img src="https://img.shields.io/badge/Lightning-L402%20%7C%20x402%20%7C%20MPP-F7931A" alt="HTTP payments with L402, x402 and MPP"></a>
</p>

<p align="center">
  <a href="https://aionwc.readthedocs.io/">Documentation</a>
  &middot; <a href="https://aionwc.readthedocs.io/en/latest/api.html">API reference</a>
  &middot; <a href="#quickstart">Quickstart</a>
  &middot; <a href="#development">Development</a>
</p>

`aionwc` is an asyncio client for Lightning wallets that support
[Nostr Wallet Connect (NIP-47)](https://github.com/nostr-protocol/nips/blob/master/47.md).
Give it a wallet connection URI to check a balance, create invoices, make
payments, and query transactions. The core has one required Python dependency,
`websockets`.

The package also provides HTTP payment clients and FastAPI
dependencies for L402, x402 Lightning, and MPP Lightning charge. Your application
supplies its own state management through `PaymentStore`.

## Installation

Requires **Python 3.11+** and a wallet-issued `nostr+walletconnect://` URI.

```console
python -m pip install aionwc
```

With Poetry or uv, add the dependency from your application's directory.

```console
poetry add aionwc
uv add aionwc
```

For NIP-04 wallets on systems without OpenSSL AES-256-CBC, install the
optional Python AES backend.

```console
python -m pip install "aionwc[nip04-fallback]"
```

## Quickstart

Make `NWC_URI` available to your process through your application's secret
configuration. The URI contains the wallet's private key.

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
    print(info.get("alias", "Lightning wallet"))
    print(f"Balance {balance_msat} msat")


if __name__ == "__main__":
    asyncio.run(main())
```

Amounts use **integer millisatoshis** throughout the API. One satoshi is
1,000 millisatoshis. Each operation manages its own WebSocket connection,
so independent calls can run concurrently on the same client.

## Wallet operations

| Method | Use |
| --- | --- |
| `get_info()` | Read wallet metadata and supported methods. |
| `get_balance()` | Read the balance as an integer in millisatoshis. |
| `make_invoice(amount_msat, description=...)` | Create a BOLT11 invoice to receive payment. |
| `pay_invoice(invoice, amount_msat=...)` | Pay a BOLT11 invoice and receive the wallet's confirmation. |
| `lookup_invoice(payment_hash=...)` | Read invoice details and settlement state. Also accepts `invoice=...`. |
| `list_transactions(transaction_type=..., limit=...)` | Filter and paginate incoming or outgoing transactions. |
| `request(method, params)` | Call another NIP-47 method supported by the wallet. |

Invoice and payment operations return the wallet's result dictionary.
`list_transactions()` returns a list of transaction dictionaries. The default
deadline for a call is 30 seconds, including connection and encryption discovery.

See the wallet guide for invoice options, history filters, and examples.
[Wallet operations](https://aionwc.readthedocs.io/en/latest/wallet.html)

## HTTP payments

Install the `payments` extra to use the HTTP payment APIs, available since
version 0.2.0.

```console
python -m pip install "aionwc[payments]>=0.2.0"
```

To expose paid endpoints with FastAPI, install the `fastapi` extra.

```console
python -m pip install "aionwc[fastapi]>=0.2.0"
```

### Pay for an API

Use an HTTP client and NWC wallet owned by your application. `fetch()` detects
a supported 402 challenge, validates the invoice, pays within your limit,
and retries the HTTP request once.

The default header preference is L402/LSAT, MPP, then x402. Pass
`protocol_order=("x402", "mpp", "l402")` to `PaymentClient` to change it.
L402 challenges in the JSON response body are considered after headers
when `l402` is included in the configured order.

```python
import httpx

from aionwc import NWCClient
from aionwc.payments import PaymentClient


async def get_report(wallet: NWCClient, http: httpx.AsyncClient):
    payer = PaymentClient(wallet, http)
    result = await payer.fetch(
        "GET",
        "https://api.example.com/report",
        max_amount_msat=21_000,
    )
    result.response.raise_for_status()
    return result.response.json()
```

The limit covers the invoice amount. Routing fees follow the wallet's policy.
A `PaymentInterrupted` exception retains the challenge and any available
credential so the application can reconcile settlement and resume with the
existing proof.

### Charge for a FastAPI endpoint

Inject your application's `PaymentStore` to retain challenges and atomically
consume single-use proofs. The dependency verifies payment before the endpoint
runs.

```python
import os

from fastapi import Depends, FastAPI

from aionwc import NWCClient
from aionwc.fastapi import require_payment
from aionwc.payment_server import PaymentServer, PaymentStore


def create_app(store: PaymentStore) -> FastAPI:
    app = FastAPI()
    receiver = PaymentServer(
        NWCClient(os.environ["NWC_RECEIVER_URI"]),
        origin="https://api.example.com",
        store=store,
    )

    @app.get("/report", dependencies=[Depends(require_payment(
        receiver, protocol="mpp", amount_msat=21_000,
    ))])
    async def report():
        return {"report": "Paid content"}

    return app
```

| Protocol | Supported flow |
| --- | --- |
| **L402 / LSAT** | Macaroon and payment preimage. The server's original credential can be reused for the matching request until expiry. |
| **x402 Lightning** | Version 2 `exact` on `lnbtc`, with `http:1` request binding and single-use settlement. |
| **MPP Lightning** | `charge` intent with whole-satoshi amounts, single-use credentials, and a payment receipt. |

The HTTP payments guide includes a complete application-owned SQLAlchemy
`PaymentStore`, FastAPI lifespan integration, request binding, and payment
recovery.
[HTTP payments guide](https://github.com/Sats-Lottu/aionwc/blob/main/docs/payments.rst)

## Encryption and wallet compatibility

The client prefers **NIP-44 v2** when the wallet advertises support and falls
back to **NIP-04** when no valid information event or encryption tag is
available. Set `NWCClient(uri, encryption="nip44_v2")` to require NIP-44.
Responses are checked for the wallet's signature and correlation with the
published request.

For secp256k1 operations, the client prefers the system's `libsecp256k1`
with ECDH, extrakeys, and Schnorr support. OpenSSL's `libcrypto` is the next
choice, followed by Python curve arithmetic. The Python fallback uses
variable-time arithmetic. On Windows, the client searches for
`secp256k1.dll` or `libsecp256k1.dll` and can use the OpenSSL DLL bundled with
CPython.

NIP-04 uses OpenSSL AES-256-CBC or the optional `pyaes` backend. NIP-44 works
independently of both AES backends.
[Encryption and compatibility](https://aionwc.readthedocs.io/en/latest/encryption.html)

## Handle payment errors

`NWCWalletError` exposes the wallet's `code` and `message`.
`NWCRelayError` and its subclass `NWCTimeoutError` can include the signed
`request_id` when publication was attempted.

Relay fallback ends at the first publication attempt. If a payment times out
or the connection drops after publication, query `lookup_invoice()` before
attempting another payment. Keep wallet URIs and payment credentials out of
logs and source control.

## Development

Install the checkout with its documentation dependencies and the extras used
by the full suite of tests that run without Docker.

```console
poetry install --with docs --extras "nip04-fallback fastapi"
poetry run pytest --cov=aionwc --cov-report=term-missing --cov-report=html --cov-fail-under=100
poetry check --lock --strict
poetry build
poetry run twine check --strict dist/*
```

For integration tests, start Docker and install the integration group.

```console
poetry install --with integration --extras "nip04-fallback fastapi"
poetry run pytest -m integration
poetry run pytest -o addopts= --cov=aionwc --cov-report=term-missing --cov-fail-under=100
```

Testcontainers starts LNbits and a local Nostr relay with fresh wallets and
LNbits' `FakeWallet` funding source. Fresh wallet pairs isolate each test. The
suite checks NWC invoice creation, settlement, preimages, balances, and FastAPI
payment flows for L402, MPP, and x402, including replay and request binding.
The first run downloads container images and the LNbits NWC Provider extension.
GitHub Actions runs the Docker integration on pull requests, manual runs, and
releases. Publishing requires both the standard suite and integration to pass.

Build the documentation locally.

```console
poetry run sphinx-build -M html docs docs/_build -W --keep-going
```

Open `docs/_build/html/index.html` to preview the site. To install a locally
built package, use the generated wheel from `dist/`.

```console
python -m pip install dist/aionwc-0.2.0-py3-none-any.whl
```

Release validation and PyPI Trusted Publishing are documented in the release
guide.
[Release guide](https://github.com/Sats-Lottu/aionwc/blob/main/.github/RELEASING.md)

## License and acknowledgements

Released under the MIT license and maintained by **Sats-Lottu**.
The project is inspired by eddieoz's `nwc-agent`, with adapted portions retaining
their original MIT attribution.
[License](https://github.com/Sats-Lottu/aionwc/blob/main/LICENSE)
&middot; [nwc-agent](https://github.com/eddieoz/nwc-agent)
