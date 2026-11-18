"""Reject malformed terms and credentials before paying or serving a resource."""

import base64
import time
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

httpx = pytest.importorskip("httpx")
fastapi = pytest.importorskip("fastapi")

from aionwc import NWCProtocolError, NWCRelayError
from aionwc import _payment_wire as wire
from aionwc.fastapi import require_payment
from aionwc.payment_server import PaymentRequired, PaymentServer, _read_credential
from aionwc.payments import PaymentClient, PaymentError, PaymentInterrupted
from test_http_payments import ApplicationPaymentStore, FakeWallet


@pytest.fixture
async def setup_payment(invoice_factory):
    wallet, store = FakeWallet(invoice_factory), ApplicationPaymentStore()
    server = PaymentServer(wallet, store=store, origin="https://api.example.com")
    request = httpx.Request("POST", "https://api.example.com/paid", content=b"body")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500))) as http:
        yield wallet, store, server, request, PaymentClient(wallet, http)


async def issue(server, request, protocol):
    with pytest.raises(PaymentRequired) as error:
        await server.require_payment(request, protocol=protocol, amount_msat=1000)
    return httpx.Response(402, request=request, headers=error.value.headers)


@pytest.mark.parametrize("function,value,error", [
    (wire.origin_of, httpx.URL("/relative"), "absolute HTTP"),
    (wire.origin_of, httpx.URL("https://user@example.com"), "absolute HTTP"),
    (wire.origin_of, httpx.URL("https://example.com/#fragment"), "absolute HTTP"),
    (wire.decode_json, "a" * 32769, "too long"),
    (wire.decode_json, "***", "Malformed"),
    (wire.decode_json, wire.encode_json([]), "JSON object"),
    (wire.decode_json, base64.b64encode(b'{"a":1,"a":2}').decode(), "Malformed"),
    (wire.string_field, "", "Missing"), (wire.string_field, 1, "Missing"),
    (wire.decimal_amount, "0", "positive decimal"),
    (wire.decimal_amount, "-1", "positive decimal"),
    (wire.decimal_amount, 1, "positive decimal"),
    (wire.preimage_hash, "00", "32-byte"),
    (wire.parse_timestamp, "tomorrow", "expiration timestamp"),
    (wire.parse_timestamp, "2026-99-01T00:00:00Z", "expiration timestamp"),
    (wire.binding_headers, ("X-Header",), "Bound headers"),
    (wire.binding_headers, ("b", "a"), "Bound headers"),
    (wire.binding_headers, ("a", "a"), "Bound headers"),
    (wire.binding_headers, ("payment-signature",), "Bound headers"),
], ids=["relative-url", "userinfo-url", "fragment-url", "oversized-header", "invalid-base64",
        "nonobject-json", "duplicate-json", "empty-string", "non-string", "zero-amount",
        "negative-amount", "non-string-amount", "short-preimage", "invalid-timestamp",
        "invalid-date", "uppercase-header", "unsorted-headers", "duplicate-headers", "credential-header"])
def test_invalid_wire_fields(function, value, error):
    with pytest.raises(PaymentError, match=error):
        function(value)


def test_oversized_auth_challenge_is_ignored():
    headers = httpx.Headers([("www-authenticate", "L402 " + "a" * 32768),
                            ("www-authenticate", 'Basic realm="api"')])
    assert wire.auth_challenges(headers) == []


@pytest.mark.parametrize("value,error", [(b"\xff", "ASCII"), (b"\x00", "Invalid bound header")])
def test_invalid_request_binding_header(value, error):
    request = httpx.Request("POST", "https://api.example.com", headers=[(b"x-account", value)])
    with pytest.raises(PaymentError, match=error):
        wire.request_hash(request, ("x-account",), wire.X402_DOMAIN)


def test_invoice_validation_rejects_invalid_encoding_and_terms(invoice_factory):
    with pytest.raises(PaymentError, match="Invalid BOLT11"):
        wire.decode_invoice("not-an-invoice", "bc")
    fields = [("p", bytes(32)), ("s", bytes(32)), ("d", "test")]
    now = int(time.time())
    invoices = [
        invoice_factory("lnbc", fields, timestamp=now),
        invoice_factory("lntb10p", fields, timestamp=now),
        invoice_factory("lnbc10p", fields, timestamp=now + 3600),
        invoice_factory("lnbc10p", fields + [("x", 0)], timestamp=now),
        invoice_factory("lnbc10p", fields + [("x", 1)], timestamp=now - 100),
    ]
    for invoice in invoices:
        with pytest.raises(PaymentError, match="amount, date, or network"):
            wire.decode_invoice(invoice, "bc")


@pytest.mark.parametrize("origin,network", [("https://api.example.com/path", "bc"),
                                          ("https://api.example.com", "unknown")])
def test_invalid_server_configuration(origin, network):
    with pytest.raises(ValueError, match="public HTTP origin"):
        PaymentServer(None, store=ApplicationPaymentStore(), origin=origin, network=network)


@pytest.mark.parametrize("options,error", [
    ({"protocol": "unknown"}, "Unknown HTTP"),
    ({"amount_msat": 0}, "amount_msat"), ({"amount_msat": True}, "amount_msat"),
    ({"expiry": 0}, "expiry"), ({"expiry": True}, "expiry"),
    ({"protocol": "mpp", "amount_msat": 1}, "whole satoshis"),
    ({"bound_headers": ("authorization",)}, "Authorization"),
])
async def test_server_rejects_invalid_options(setup_payment, options, error):
    wallet, store, server, request, client = setup_payment
    with pytest.raises(ValueError, match=error):
        await server.require_payment(request, **({"protocol": "l402", "amount_msat": 1000} | options))
    assert not wallet.invoices and not store.payments


@pytest.mark.parametrize("network,protocol", [("tb", "mpp"), ("bcrt", "x402")])
async def test_protocol_network_restrictions(network, protocol):
    server = PaymentServer(None, store=ApplicationPaymentStore(), origin="https://api.example.com", network=network)
    with pytest.raises(ValueError):
        await server.require_payment(httpx.Request("GET", server.origin), protocol=protocol, amount_msat=1000)


async def test_server_rejects_wrong_request_origin(setup_payment):
    wallet, store, server, request, client = setup_payment
    with pytest.raises(PaymentError, match="origin"):
        await server.require_payment(httpx.Request("GET", "https://other.example"), protocol="l402", amount_msat=1000)
    assert not wallet.invoices


@pytest.mark.parametrize("mismatch", ["amount", "hash", "expiry", "reused"])
async def test_rejects_inconsistent_wallet_invoice(setup_payment, monkeypatch, mismatch):
    wallet, store, server, request, client = setup_payment
    invoice = await wallet.make_invoice(2000 if mismatch == "amount" else 1000, description="test", expiry=300)
    if mismatch == "hash":
        invoice["payment_hash"] = "00" * 32
    monkeypatch.setattr(wallet, "make_invoice", AsyncMock(return_value=invoice))
    if mismatch == "expiry":
        # The invoice is live but exceeds the shorter validity requested by this server.
        from aionwc._bolt11 import parse_invoice
        monkeypatch.setattr("aionwc.payment_server.time", type("Clock", (), {
            "time": staticmethod(lambda: parse_invoice(invoice["invoice"]).date + 301),
        }))
    if mismatch == "reused":
        monkeypatch.setattr(store, "save", AsyncMock(return_value=False))
    with pytest.raises(PaymentError):
        await server.require_payment(request, protocol="l402", amount_msat=1000)
    assert not store.payments


@pytest.mark.parametrize("protocol,credential,error", [
    ("l402", "a" * 32769, "too long"),
    ("l402", "Basic token", "scheme"),
    ("l402", "L402 missing-colon", "scheme"),
    ("mpp", "Bearer token", "scheme"),
    ("x402", wire.encode_json({"x402Version": True}), "v2 credential"),
    ("x402", wire.encode_json({"x402Version": 2, "resource": {"url": "https://other.example"}}), "different resource"),
], ids=["oversized", "wrong-l402-scheme", "missing-separator", "wrong-mpp-scheme", "boolean-version", "wrong-resource"])
def test_invalid_credentials(protocol, credential, error):
    with pytest.raises(PaymentError, match=error):
        _read_credential(protocol, credential, "https://api.example.com/paid")


async def test_unissued_l402_proof_is_rejected(setup_payment):
    wallet, store, server, request, client = setup_payment
    request.headers["authorization"] = "L402 dGVzdA==:" + "00" * 32
    with pytest.raises(PaymentRequired) as error:
        await server.require_payment(request, protocol="l402", amount_msat=1000)
    assert error.value.status_code == 401 and not wallet.invoices


async def test_malformed_l402_preimage_is_rejected_without_issuing_an_invoice(setup_payment):
    wallet, store, server, request, client = setup_payment
    request.headers["authorization"] = "L402 dGVzdA==:invalid-preimage"
    with pytest.raises(PaymentRequired) as error:
        await server.require_payment(request, protocol="l402", amount_msat=1000)
    assert error.value.status_code == 401 and not wallet.invoices and not store.payments


@pytest.mark.parametrize("field,value", [
    ("payment_hash", "00" * 32), ("protocol", "mpp"), ("scope", "other"),
    ("amount_msat", 2000), ("expiry_seconds", 600), ("valid_until", 0), ("accepted", "changed"),
])
async def test_changed_stored_terms_cannot_authorize(setup_payment, field, value):
    wallet, store, server, request, client = setup_payment
    challenge = client.challenge(await issue(server, request, "l402"))
    original = store.payments[challenge.payment_hash]
    store.payments[challenge.payment_hash] = replace(original, **{field: value})
    request.headers.update(challenge.credential(wallet.invoices[challenge.invoice]).headers_for(request.url))
    with pytest.raises(PaymentRequired) as error:
        await server.require_payment(request, protocol="l402", amount_msat=1000)
    assert error.value.status_code == 401


def test_client_rejects_unsupported_network():
    with pytest.raises(ValueError, match="network"):
        PaymentClient(None, None, network="unknown")


async def test_challenge_rejects_non402_and_invalid_macaroon(setup_payment):
    wallet, store, server, request, client = setup_payment
    with pytest.raises(PaymentError, match="HTTP 402"):
        client.challenge(httpx.Response(200, request=request))
    with pytest.raises(PaymentError, match="macaroon"):
        client.challenge(httpx.Response(402, request=request, headers={
            "WWW-Authenticate": 'L402 macaroon="!", invoice="not-an-invoice"',
        }))
    challenge = client.challenge(await issue(server, request, "l402"))
    with pytest.raises(PaymentError, match="does not match"):
        challenge.credential("00" * 32)


@pytest.mark.parametrize("change", ["header", "digest", "currency", "amount", "network", "paymentHash", "expires"])
async def test_mpp_rejects_mismatched_challenge(setup_payment, change):
    wallet, store, server, request, client = setup_payment
    response = await issue(server, request, "mpp")
    _, fields = wire.auth_challenges(response.headers)[0]
    if change in {"header", "digest", "expires"}:
        fields[change] = {"header": "Authorization", "digest": "wrong", "expires": "2000-01-01T00:00:00Z"}[change]
    else:
        payment = wire.decode_json(fields["request"], urlsafe=True)
        if change in {"network", "paymentHash"}:
            payment["methodDetails"][change] = "wrong"
        else:
            payment[change] = "BTC" if change == "currency" else "2"
        fields["request"] = wire.encode_json(payment, urlsafe=True)
    response.headers["www-authenticate"] = wire.auth_header("Payment", fields)
    with pytest.raises(PaymentError):
        client.challenge(response)
    assert wallet.payments == []


@pytest.mark.parametrize("change", ["version", "resource", "accepts", "nonobject", "scheme", "amount"])
async def test_x402_rejects_invalid_requirements(setup_payment, change):
    wallet, store, server, request, client = setup_payment
    response = await issue(server, request, "x402")
    payment = wire.decode_json(response.headers["payment-required"])
    if change == "version":
        payment["x402Version"] = True
    elif change == "resource":
        payment["resource"]["url"] = "https://other.example"
    elif change == "accepts":
        payment["accepts"] = {}
    elif change == "nonobject":
        payment["accepts"] = [None, "invalid"]
    else:
        payment["accepts"][0][change] = "unsupported" if change == "scheme" else "2000"
    response.headers["payment-required"] = wire.encode_json(payment)
    with pytest.raises(PaymentError):
        client.challenge(response)
    assert wallet.payments == []


@pytest.mark.parametrize("change", ["budget", "network", "expires", "hash", "amount"])
async def test_pay_revalidates_challenge_before_wallet_call(setup_payment, change):
    wallet, store, server, request, client = setup_payment
    challenge = client.challenge(await issue(server, request, "l402"))
    changes = {"network": {"_network": "tb"}, "expires": {"expires_at": 0},
               "hash": {"payment_hash": "00" * 32}, "amount": {"amount_msat": 1}}
    if change != "budget":
        challenge = replace(challenge, **changes[change])
    with pytest.raises(ValueError if change == "budget" else PaymentError):
        await client.pay(challenge, max_amount_msat=True if change == "budget" else 1000)
    assert wallet.payments == []


@pytest.mark.parametrize("error,interrupted", [
    (NWCRelayError("not sent"), False), (NWCRelayError("sent", request_id="id"), True),
    (NWCProtocolError("invalid response"), True), (None, True),
])
async def test_wallet_failure_reports_whether_payment_may_have_happened(setup_payment, monkeypatch, error, interrupted):
    wallet, store, server, request, client = setup_payment
    challenge = client.challenge(await issue(server, request, "l402"))
    pay = AsyncMock(side_effect=error, return_value={"preimage": "00" * 32})
    monkeypatch.setattr(wallet, "pay_invoice", pay)
    with pytest.raises(PaymentInterrupted if interrupted else NWCRelayError) as raised:
        await client.pay(challenge, max_amount_msat=1000)
    if interrupted:
        assert raised.value.challenge is challenge and raised.value.credential is None
    pay.assert_awaited_once_with(challenge.invoice)


async def test_fetch_rejects_streaming_body_before_sending(setup_payment):
    wallet, store, server, request, client = setup_payment

    async def stream():
        yield b"data"

    with pytest.raises(PaymentError, match="replayable body"):
        await client.fetch("POST", request.url, content=stream(), max_amount_msat=1000)
    assert not wallet.payments


async def test_fetch_preserves_existing_application_authorization(setup_payment):
    wallet, store, server, request, client = setup_payment
    challenge_response = await issue(server, request, "l402")
    calls = []

    async def respond(incoming):
        calls.append(incoming)
        return httpx.Response(402, headers=challenge_response.headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
        with pytest.raises(PaymentError, match="overwrite"):
            await PaymentClient(wallet, http).fetch("POST", request.url, headers={"authorization": "Bearer application"}, max_amount_msat=1000)
    assert len(calls) == 1 and calls[0].headers["authorization"] == "Bearer application"
    assert wallet.payments == []


@pytest.mark.parametrize("invalid", ["origin", "raw_path", "query_string"])
async def test_fastapi_rejects_invalid_request_target(setup_payment, invalid):
    wallet, store, server, request, client = setup_payment
    scope = {"type": "http", "method": "POST", "scheme": "https", "path": "/paid",
             "raw_path": b"/paid", "query_string": b"", "headers": [(b"host", b"api.example.com")]}
    if invalid == "origin":
        scope["headers"] = [(b"host", b"other.example")]
    else:
        scope[invalid] = b"\xff"
    dependency = require_payment(server, protocol="l402", amount_msat=1000)
    with pytest.raises(fastapi.HTTPException) as error:
        await dependency(fastapi.Request(scope), fastapi.Response())
    assert error.value.status_code == 400 and not wallet.invoices
