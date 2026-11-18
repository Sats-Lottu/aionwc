# Changelog

## [0.2.0] - 2026-11-17

### Added

- Pay for HTTP resources with L402/LSAT, MPP Lightning charge, and x402 v2
  Lightning using an NWC wallet and a caller-owned HTTP client.
- Charge for FastAPI endpoints with invoice issuance, request binding,
  verified preimages, receipts, and replay protection.
- Configure protocol detection priority and restrict accepted protocols.
  The default is L402, MPP, then x402, with an L402 JSON body fallback.
- Supply application-owned challenge storage through the asynchronous
  `PaymentStore` interface. The guide includes a SQLAlchemy implementation.
- Decode and verify BOLT11 invoices with the adapted internal implementation
  and existing secp256k1 arithmetic.
- Install HTTP support through the `payments` and `fastapi` extras.

### Fixed

- Return HTTP 400 for malformed FastAPI query strings and request targets
  before attempting invoice issuance or verification.

### Documentation and validation

- Refresh the README with the project logo, badges, and payment examples.
- Cover all executable library lines with 294 tests that run without Docker.
- Verify the NWC invoice lifecycle and all three HTTP protocols in four
  Docker integration tests using LNbits and a Nostr relay with test funds.
- Require coverage and Docker integration checks before PyPI publication.

[0.2.0]: https://github.com/Sats-Lottu/aionwc/compare/v0.1.1...v0.2.0
