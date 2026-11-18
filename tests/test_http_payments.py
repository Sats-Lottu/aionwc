import asyncio
import hashlib
import json
import secrets
import time
from importlib.util import find_spec

import pytest

if any(find_spec(module) is None for module in ("fastapi", "httpx")):
    pytest.skip("Install the FastAPI extra to run HTTP payment tests", allow_module_level=True)

import fastapi
import httpx

from aionwc import NWCTimeoutError
from aionwc._bolt11 import parse_invoice
from aionwc._payment_wire import X402_DOMAIN, decode_json, encode_json, request_hash
from aionwc.fastapi import require_payment
from aionwc.payment_server import PaymentServer
from aionwc.payments import PaymentClient, PaymentError, PaymentInterrupted


class FakeWallet:
    def __init__(self, invoice_factory):
        self.invoices = {}
        self.payments = []
        self._invoice_factory = invoice_factory

    async def make_invoice(self, amount_msat, *, description=None, description_hash=None, expiry):
        preimage = secrets.token_hex(32)
        payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        fields = [("p", bytes.fromhex(payment_hash)), ("s", secrets.token_bytes(32)), ("x", expiry)]
        if description_hash is None:
            fields.append(("d", description))
        else:
            fields.append(("h", bytes.fromhex(description_hash)))
        invoice = self._invoice_factory(f"lnbc{amount_msat * 10}p", fields, timestamp=int(time.time()))
        self.invoices[invoice] = preimage
        return {"invoice": invoice, "payment_hash": payment_hash}

    async def pay_invoice(self, invoice):
        self.payments.append(invoice)
        return {"preimage": self.invoices[invoice]}


class ApplicationPaymentStore:
    """Test application state with atomic insertion and consumption."""

    def __init__(self):
        self.payments = {}
        self.consumed = set()
        self.lock = asyncio.Lock()

    async def save(self, payment):
        async with self.lock:
            if payment.payment_hash in self.payments:
                return False
            self.payments[payment.payment_hash] = payment
            return True

    async def get(self, payment_hash):
        return self.payments.get(payment_hash)

    async def consume(self, payment_hash):
        async with self.lock:
            if payment_hash not in self.payments or payment_hash in self.consumed:
                return False
            self.consumed.add(payment_hash)
            return True


@pytest.fixture
def store():
    return ApplicationPaymentStore()


def paid_app(wallet, store, protocol, *, bound_headers=("content-type",)):
    app = fastapi.FastAPI()
    app.state.served = 0
    server = PaymentServer(wallet, store=store, origin="https://api.example.com")
    gate = require_payment(server, protocol=protocol, amount_msat=21_000, bound_headers=bound_headers)

    @app.post("/paid/{name}")
    async def paid(name: str, request: fastapi.Request, receipt=fastapi.Depends(gate)):
        app.state.served += 1
        return {"name": name, "amount_msat": receipt.amount_msat, "body": await request.json()}

    return app


def app_client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://api.example.com")


@pytest.mark.parametrize("protocol", ["l402", "mpp", "x402"])
async def test_fastapi_payment_round_trip(store, invoice_factory, protocol):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, protocol)
    async with app_client(app) as http:
        result = await PaymentClient(wallet, http).fetch(
            "POST", "/paid/caf%C3%A9?q=a%2Fb&q=b", json={"work": 1}, max_amount_msat=21_000,
        )
    assert app.state.served == 1
    assert len(wallet.payments) == 1
    assert result.response.status_code == 200
    assert result.response.json() == {"name": "café", "amount_msat": 21_000, "body": {"work": 1}}
    assert result.response.headers["cache-control"] == "no-store"
    assert result.credential is not None
    payment_hash = parse_invoice(wallet.payments[0]).payment_hash
    if protocol == "mpp":
        assert decode_json(result.response.headers["Payment-Receipt"], urlsafe=True)["reference"] == payment_hash
    if protocol == "x402":
        assert decode_json(result.response.headers["PAYMENT-RESPONSE"])["transaction"] == payment_hash


@pytest.mark.parametrize("extra_headers", [
    {},
    {"WWW-Authenticate": 'Basic realm="proxy"'},
    {"PAYMENT-REQUIRED": encode_json({
        "x402Version": 2, "resource": {"url": "https://api.example.com/paid"},
        "accepts": [{"scheme": "exact", "network": "eip155:8453", "asset": "USDC"}],
    })},
    {"PAYMENT-REQUIRED": "not-base64"},
])
async def test_detects_l402_json_body_and_retries(invoice_factory, extra_headers):
    wallet = FakeWallet(invoice_factory)
    invoice = await wallet.make_invoice(21_000, description="Body challenge", expiry=300)
    calls = []

    async def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(402, headers=extra_headers, json={
                "l402": {"macaroon": "dGVzdA==", "invoice": invoice["invoice"]},
            })
        expected = "L402 dGVzdA==:" + wallet.invoices[invoice["invoice"]]
        assert request.headers["Authorization"] == expected
        return httpx.Response(200, json={"content": "Paid resource"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await PaymentClient(wallet, http).fetch(
            "GET", "https://api.example.com/paid", max_amount_msat=21_000,
        )
    assert result.response.status_code == 200
    assert wallet.payments == [invoice["invoice"]] and len(calls) == 2


@pytest.mark.parametrize("combined_auth_header", [False, True])
@pytest.mark.parametrize("l402_scheme", ["L402", "LSAT"])
async def test_l402_header_takes_priority_over_mpp_and_x402(
    store, invoice_factory, combined_auth_header, l402_scheme,
):
    wallet = FakeWallet(invoice_factory)
    responses = {}
    for protocol in ("l402", "mpp", "x402"):
        async with app_client(paid_app(wallet, store, protocol)) as http:
            responses[protocol] = await http.post("/paid/data", json={})
    mpp = responses["mpp"].headers["WWW-Authenticate"]
    l402 = responses["l402"].headers["WWW-Authenticate"].replace("L402", l402_scheme.lower(), 1)
    auth_headers = [("WWW-Authenticate", mpp), ("WWW-Authenticate", l402)]
    if combined_auth_header:
        auth_headers = [("wWw-AuThEnTiCaTe", mpp + ", " + l402)]
    headers = [*auth_headers, ("pAyMeNt-ReQuIrEd", responses["x402"].headers["PAYMENT-REQUIRED"])]
    response = httpx.Response(402, headers=headers, request=responses["l402"].request)
    async with app_client(paid_app(wallet, store, "l402")) as http:
        challenge = PaymentClient(wallet, http).challenge(response)
    assert challenge.protocol == "l402" and wallet.payments == []
    assert challenge.credential(wallet.invoices[challenge.invoice]).value.startswith(l402_scheme + " ")


@pytest.mark.parametrize("header_protocol", ["mpp", "x402"])
async def test_supported_headers_take_priority_over_l402_body(store, invoice_factory, header_protocol):
    wallet = FakeWallet(invoice_factory)
    body_invoice = await wallet.make_invoice(21_000, description="Body challenge", expiry=300)
    async with app_client(paid_app(wallet, store, header_protocol)) as http:
        original = await http.post("/paid/data", json={})
        response = httpx.Response(402, headers=original.headers, request=original.request, json={
            "l402": {"macaroon": "dGVzdA==", "invoice": body_invoice["invoice"]},
        })
        if header_protocol == "mpp":
            async with app_client(paid_app(wallet, store, "x402")) as other_http:
                x402 = await other_http.post("/paid/data", json={})
                response.headers["payment-required"] = x402.headers["payment-required"]
        challenge = PaymentClient(wallet, http).challenge(response)
    assert challenge.protocol == header_protocol and wallet.payments == []


@pytest.mark.parametrize("protocol_order", [
    ("mpp", "l402", "x402"), ("x402", "mpp", "l402"), ("mpp",),
])
async def test_fetch_uses_configured_protocol_order(store, invoice_factory, protocol_order):
    wallet = FakeWallet(invoice_factory)
    apps = {}
    responses = {}
    for protocol in ("l402", "mpp", "x402"):
        apps[protocol] = paid_app(wallet, store, protocol)
        async with app_client(apps[protocol]) as http:
            responses[protocol] = await http.post("/paid/data", json={})
    headers = [
        ("WWW-Authenticate", responses["l402"].headers["WWW-Authenticate"]),
        ("WWW-Authenticate", responses["mpp"].headers["WWW-Authenticate"]),
        ("PAYMENT-REQUIRED", responses["x402"].headers["PAYMENT-REQUIRED"]),
    ]
    expected = protocol_order[0]
    requests = []
    async with app_client(apps[expected]) as receiver:
        async def handler(request):
            requests.append(request)
            if len(requests) == 1:
                return httpx.Response(402, headers=headers)
            return await receiver.send(request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            payer = PaymentClient(wallet, http, protocol_order=protocol_order)
            result = await payer.fetch("POST", "https://api.example.com/paid/data", json={}, max_amount_msat=21_000)
    assert result.response.status_code == 200
    assert apps[expected].state.served == 1
    assert sum(app.state.served for app in apps.values()) == 1
    assert len(wallet.payments) == 1 and len(requests) == 2


async def test_protocol_order_snapshots_mutable_configuration(store, invoice_factory):
    wallet = FakeWallet(invoice_factory)
    async with app_client(paid_app(wallet, store, "l402")) as l402_http:
        l402 = await l402_http.post("/paid/data", json={})
    async with app_client(paid_app(wallet, store, "mpp")) as http:
        mpp = await http.post("/paid/data", json={})
        order = ["mpp", "l402"]
        payer = PaymentClient(wallet, http, protocol_order=order)
        order.reverse()
        response = httpx.Response(402, request=mpp.request, headers=[
            ("WWW-Authenticate", l402.headers["WWW-Authenticate"]),
            ("WWW-Authenticate", mpp.headers["WWW-Authenticate"]),
        ])
        assert payer.challenge(response).protocol == "mpp"
    assert wallet.payments == []


@pytest.mark.parametrize("location", ["header", "body"])
async def test_omitted_protocol_is_excluded_from_detection(invoice_factory, location):
    wallet = FakeWallet(invoice_factory)
    invoice = await wallet.make_invoice(21_000, description="L402 resource", expiry=300)
    headers = {}
    body = {}
    if location == "header":
        headers["WWW-Authenticate"] = 'L402 macaroon="dGVzdA==", invoice="' + invoice["invoice"] + '"'
    else:
        body = {"l402": {"macaroon": "dGVzdA==", "invoice": invoice["invoice"]}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(402, headers=headers, json=body),
    )) as http:
        payer = PaymentClient(wallet, http, protocol_order=("mpp", "x402"))
        with pytest.raises(PaymentError):
            await payer.fetch("GET", "https://api.example.com/paid", max_amount_msat=21_000)
    assert wallet.payments == []


@pytest.mark.parametrize("protocol_order", [
    (), [], ("l402", "l402"), ("unknown",), ("LSAT",), "mpp", {"l402", "mpp"}, None,
])
async def test_invalid_protocol_order_is_rejected(invoice_factory, protocol_order):
    async with httpx.AsyncClient() as http:
        with pytest.raises(ValueError, match="protocol_order"):
            PaymentClient(FakeWallet(invoice_factory), http, protocol_order=protocol_order)


@pytest.mark.parametrize("body", [
    b"not JSON", b"[]", b'{"l402": []}', b'{"l402": {}}',
    b'{"l402": {"invoice": "invalid"}}',
    b'{"l402": {"macaroon": "dGVzdA==", "invoice": "invalid"}}',
])
async def test_invalid_body_challenges_do_not_trigger_payment(invoice_factory, body):
    wallet = FakeWallet(invoice_factory)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(402, content=body))) as http:
        with pytest.raises(PaymentError):
            await PaymentClient(wallet, http).fetch(
                "GET", "https://api.example.com/paid", max_amount_msat=21_000,
            )
    assert wallet.payments == []


async def test_duplicate_body_fields_are_rejected_before_payment(invoice_factory):
    wallet = FakeWallet(invoice_factory)
    invoice = await wallet.make_invoice(21_000, description="Ambiguous challenge", expiry=300)
    fields = {"macaroon": "dGVzdA==", "invoice": invoice["invoice"]}
    body = '{"l402": {}, "l402": ' + json.dumps(fields) + '}'
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(402, text=body))) as http:
        with pytest.raises(PaymentError):
            await PaymentClient(wallet, http).fetch(
                "GET", "https://api.example.com/paid", max_amount_msat=21_000,
            )
    assert wallet.payments == []


async def test_non_402_response_is_returned_without_paying(invoice_factory):
    wallet = FakeWallet(invoice_factory)
    invoice = await wallet.make_invoice(21_000, description="Unpaid resource", expiry=300)
    response = httpx.Response(200, json={"l402": {"macaroon": "dGVzdA==", "invoice": invoice["invoice"]}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response)) as http:
        result = await PaymentClient(wallet, http).fetch(
            "GET", "https://api.example.com/paid", max_amount_msat=21_000,
        )
    assert result.response.status_code == 200 and result.credential is None
    assert wallet.payments == []


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
async def test_application_store_controls_replay_across_concurrent_servers(store, invoice_factory, protocol):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, protocol)
    other_app = paid_app(wallet, store, protocol)
    async with app_client(app) as http, app_client(other_app) as other_http:
        payer = PaymentClient(wallet, http)
        url = "https://api.example.com/paid/data"
        initial = await http.post(url, json={"count": 1})
        assert initial.status_code == 402
        assert initial.headers["cache-control"] == "no-store"
        assert wallet.payments == [] and app.state.served == 0
        proof = await payer.pay(payer.challenge(initial), max_amount_msat=21_000)
        headers = proof.headers_for(url)
        changed = await http.post(url, headers=headers, json={"count": 2})
        assert changed.status_code == 402
        retries = await asyncio.gather(
            http.post(url, headers=headers, json={"count": 1}),
            other_http.post(url, headers=headers, json={"count": 1}),
        )
        assert sorted(reply.status_code for reply in retries) == [200, 402]
        assert app.state.served + other_app.state.served == 1
    restarted = paid_app(wallet, store, protocol)
    async with app_client(restarted) as http:
        replay = await http.post(url, headers=headers, json={"count": 1})
    assert replay.status_code == 402 and restarted.state.served == 0


def test_server_construction_uses_application_state_only(store, invoice_factory, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    PaymentServer(FakeWallet(invoice_factory), store=store, origin="https://api.example.com")
    assert list(tmp_path.iterdir()) == []
    assert store.payments == {} and store.consumed == set()


@pytest.mark.parametrize("operation", ["save", "get", "consume"])
async def test_application_store_failure_prevents_resource_delivery(store, invoice_factory, monkeypatch, operation):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, "mpp")

    async def unavailable(*args):
        raise RuntimeError("Application store unavailable")

    async with app_client(app) as http:
        if operation == "save":
            monkeypatch.setattr(store, operation, unavailable)
            with pytest.raises(RuntimeError, match="Application store unavailable"):
                await http.post("/paid/data", json={})
        else:
            payer = PaymentClient(wallet, http)
            initial = await http.post("/paid/data", json={})
            proof = await payer.pay(payer.challenge(initial), max_amount_msat=21_000)
            monkeypatch.setattr(store, operation, unavailable)
            with pytest.raises(RuntimeError, match="Application store unavailable"):
                await http.post("/paid/data", json={}, headers=proof.headers_for(initial.request.url))
    assert app.state.served == 0


async def test_mpp_with_existing_authorization(store, invoice_factory):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, "mpp", bound_headers=("authorization", "content-type"))
    async with app_client(app) as http:
        result = await PaymentClient(wallet, http).fetch(
            "POST", "/paid/data", headers={"Authorization": "Bearer application-token"},
            json={}, max_amount_msat=21_000,
        )
    assert result.response.status_code == 200
    assert result.response.request.headers["Authorization"] == "Bearer application-token"
    assert result.response.request.headers["Payment-Authorization"].startswith("Payment ")


async def test_l402_reuse_and_tampering(store, invoice_factory):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, "l402")
    async with app_client(app) as http:
        payer = PaymentClient(wallet, http)
        result = await payer.fetch("POST", "/paid/data", json={}, max_amount_msat=21_000)
        same = await payer.fetch("POST", "/paid/data", json={}, max_amount_msat=21_000, credential=result.credential)
        other = await payer.fetch("POST", "/paid/other", json={}, max_amount_msat=21_000, credential=result.credential)
        bad = await http.post("/paid/data", json={}, headers={"Authorization": result.credential.value[:-64] + "00" * 32})
    assert (same.response.status_code, other.response.status_code, bad.status_code) == (200, 401, 401)
    assert app.state.served == 2 and len(wallet.payments) == 1
    with pytest.raises(PaymentError, match="origin"):
        result.credential.headers_for("https://other.example.com/paid/data")


@pytest.mark.parametrize("protocol", ["l402", "mpp", "x402"])
async def test_budget_validated_against_invoice_before_paying(store, invoice_factory, protocol):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, protocol)
    async with app_client(app) as http:
        with pytest.raises(PaymentError, match="max_amount_msat"):
            await PaymentClient(wallet, http).fetch("POST", "/paid/data", json={}, max_amount_msat=20_999)
    assert wallet.payments == [] and app.state.served == 0


async def test_x402_rejects_challenge_copied_from_another_request(store, invoice_factory):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, "x402")
    async with app_client(app) as http:
        issued = await http.post("/paid/data", json={"count": 1})
        request = http.build_request("POST", "/paid/data", json={"count": 2})
        forged = httpx.Response(402, headers=issued.headers, request=request)
        with pytest.raises(PaymentError, match="x402 Lightning invoice"):
            PaymentClient(wallet, http).challenge(forged)
    assert wallet.payments == []


def test_x402_official_http_binding_vector():
    request = httpx.Request("GET", "https://api.example.com/article/A")
    assert request_hash(request, (), X402_DOMAIN) == "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018"


async def test_retry_transport_error_keeps_proof_and_never_repays(store, invoice_factory):
    wallet = FakeWallet(invoice_factory)
    app = paid_app(wallet, store, "l402")
    async with app_client(app) as receiver:
        async def transport(request):
            if "Authorization" in request.headers:
                raise httpx.ReadTimeout("Connection lost", request=request)
            issued = await receiver.post(str(request.url), headers=request.headers, content=request.content)
            return httpx.Response(issued.status_code, headers=issued.headers)

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            with pytest.raises(PaymentInterrupted) as stopped:
                await PaymentClient(wallet, http).fetch(
                    "POST", "https://api.example.com/paid/data", json={}, max_amount_msat=21_000,
                )
        credential = stopped.value.credential
        response = await PaymentClient(wallet, receiver).fetch(
            "POST", "/paid/data", json={}, max_amount_msat=21_000, credential=credential,
        )
    assert response.response.status_code == 200 and len(wallet.payments) == 1


async def test_wallet_timeout_identifies_invoice_for_reconciliation(store, invoice_factory):
    class UncertainWallet(FakeWallet):
        async def pay_invoice(self, invoice):
            await super().pay_invoice(invoice)
            raise NWCTimeoutError("Wallet did not respond", request_id="event-id")

    wallet = UncertainWallet(invoice_factory)
    app = paid_app(wallet, store, "l402")
    async with app_client(app) as http:
        with pytest.raises(PaymentInterrupted) as stopped:
            await PaymentClient(wallet, http).fetch("POST", "/paid/data", json={}, max_amount_msat=21_000)
    assert stopped.value.challenge.invoice == wallet.payments[0]
    assert stopped.value.credential is None and app.state.served == 0
