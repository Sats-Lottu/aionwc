---
title: aionwc project memory
project: aionwc
type: index
tags:
  - agent-memory/state
---

# aionwc project memory

- Sats-Lottu maintains the package. The request flow and cryptographic primitives are based on eddieoz's `nwc-agent/scripts/nwc_wallet.py`. The sole required Python dependency is `websockets`.
- NIP-04 uses OpenSSL AES-256-CBC by default. The `nip04-fallback` extra installs `pyaes` for platforms without working OpenSSL AES. NIP-44 works independently of AES.
- secp256k1 prefers the system `libsecp256k1` for ECDH and Schnorr. OpenSSL handles curve operations when detected, with Python arithmetic available as the portability fallback. Verified native selection with OpenSSL 4 on Windows and libsecp256k1 0.5 on Debian.
- Relay fallback ends at the first publication attempt. The wallet may have processed a payment even if the client timed out or the WebSocket disconnected.
- The integration fixture uses LNbits 1.7.1, NWC Provider 1.2.1 and a local nostr-rs-relay. The fixture passed invoice creation, settlement and balance checks with `FakeWallet`.
- The Windows OpenSSL path passed all 19 official BIP340 vectors. The Python fallback passed the in-repository BIP340 and NIP-44 reference cases and uses variable-time arithmetic.
- [[README#Development|Development commands]] cover package builds, test selection and the on-demand `pytest-cov` report. Windows sandbox runs need access to Docker Desktop and loopback for the integration test.
- Documentation uses Sphinx autodoc and Furo in the optional Poetry `docs` group. Build with `poetry run sphinx-build -M html docs docs/_build -W --keep-going`. The checkout is configured for Read the Docs Community, where the GitHub repository must be imported before the documentation URL can be linked from PyPI metadata.
- The Quickstart documents installation as a dependency from PyPI or a built wheel. Source checkout commands belong in the development guide.
- The first package version is 0.1.0. GitHub Releases publish through `publish.yml` with the `pypi` environment. The pending publisher fields and the validation procedure are documented in `.github/RELEASING.md`.
