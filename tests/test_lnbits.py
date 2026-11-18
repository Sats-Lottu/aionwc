import asyncio
import hashlib
import time
from pathlib import Path
from secrets import randbelow
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from aionwc import NWCClient, NWCRelayError
from aionwc._secp256k1 import ORDER, public_key

pytestmark = pytest.mark.integration

LNBITS_IMAGE = "lnbits/lnbits:v1.7.1"
RELAY_IMAGE = "scsibug/nostr-rs-relay:0.9.0"
NWC_PROVIDER_VERSION = "1.2.1"
NWC_MANIFEST = "http://127.0.0.1:5000/static/nwcprovider-test-manifest.json"
NWC_MANIFEST_FILE = Path(__file__).parent / "data" / "nwcprovider-manifest.json"
PERMISSIONS = ("info", "balance", "invoice", "lookup", "history", "pay")
METHODS = (
    "get_info",
    "get_balance",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "pay_invoice",
)


def install_nwc_provider(api):
    releases = api.get("/api/v1/extension/nwcprovider/releases").raise_for_status().json()
    release = next(
        (item for item in releases if item["version"].lstrip("v") == NWC_PROVIDER_VERSION),
        None,
    )
    assert release is not None, f"Fixture manifest lacks nwcprovider {NWC_PROVIDER_VERSION}"
    api.post(
        "/api/v1/extension",
        json={
            "ext_id": "nwcprovider",
            "version": release["version"],
            "archive": release["archive"],
            "source_repo": release["source_repo"],
        },
    ).raise_for_status()
    api.put("/api/v1/extension/nwcprovider/enable").raise_for_status()


def register_wallet(api, name, provider, relay, *, credit_sats=0):
    wallet = api.post("/api/v1/wallet", json={"name": name}).raise_for_status().json()
    if credit_sats:
        api.put(
            "/users/api/v1/balance", json={"id": wallet["id"], "amount": credit_sats}
        ).raise_for_status()

    secret = randbelow(ORDER - 1) + 1
    api.put(
        f"/nwcprovider/api/v1/nwc/{public_key(secret).hex()}",
        headers={"X-Api-Key": wallet["adminkey"]},
        json={
            "description": name,
            "permissions": list(PERMISSIONS),
            "expires_at": int(time.time()) + 600,
            "budgets": [],
        },
    ).raise_for_status()
    query = urlencode({"relay": relay, "secret": f"{secret:064x}"})
    return f"nostr+walletconnect://{public_key(provider).hex()}?{query}"


@pytest.fixture(scope="module")
def lnbits_backend():
    # The integration dependency group is optional for the rest of the suite.
    import httpx
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.network import Network
    from testcontainers.core.wait_strategies import HttpWaitStrategy

    first_install_token = uuid4().hex
    admin_password = uuid4().hex
    provider = randbelow(ORDER - 1) + 1
    settings = {
        "FIRST_INSTALL_TOKEN": first_install_token,
        "LNBITS_ADMIN_UI": "true",
        "LNBITS_BACKEND_WALLET_CLASS": "FakeWallet",
        "LNBITS_EXTENSIONS_DEFAULT_INSTALL": "",
        "LNBITS_EXTENSIONS_MANIFESTS": NWC_MANIFEST,
    }
    network_options = {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}
    with Network(docker_network_kw={"options": network_options}) as network:
        relay = (
            DockerContainer(RELAY_IMAGE)
            .with_network(network)
            .with_network_aliases("nostr")
            .with_exposed_ports(8080)
            .waiting_for(HttpWaitStrategy(8080))
        )
        readiness = HttpWaitStrategy(5000, "/openapi.json").with_startup_timeout(90)
        lnbits = (
            DockerContainer(LNBITS_IMAGE)
            .with_network(network)
            .with_volume_mapping(
                str(NWC_MANIFEST_FILE.resolve()),
                "/app/lnbits/static/nwcprovider-test-manifest.json",
                mode="ro",
            )
            .with_exposed_ports(5000)
            .waiting_for(readiness)
        )
        for name, value in settings.items():
            lnbits.with_env(name, value)

        with relay, lnbits:
            relay_url = f"ws://{relay.get_container_host_ip()}:{relay.get_exposed_port(8080)}"
            base_url = f"http://{lnbits.get_container_host_ip()}:{lnbits.get_exposed_port(5000)}"
            with httpx.Client(base_url=base_url, timeout=60.0, trust_env=False) as api:
                setup = api.put(
                    "/api/v1/auth/first_install",
                    json={
                        "username": "aionwctest",
                        "password": admin_password,
                        "password_repeat": admin_password,
                        "first_install_token": first_install_token,
                    },
                )
                assert setup.is_success, f"LNbits first install failed: {setup.text}"
                api.headers["Authorization"] = f"Bearer {setup.json()['access_token']}"
                install_nwc_provider(api)
                configuration = api.post(
                    "/nwcprovider/api/v1/config",
                    json={"provider_key": f"{provider:064x}", "relay": "ws://nostr:8080"},
                )
                if not configuration.is_success:
                    pytest.fail(f"LNbits rejected NWC provider configuration: {configuration.status_code}")
                # The extension worker reads provider configuration on startup.
                lnbits.get_wrapped_container().restart(timeout=5)
                readiness.wait_until_ready(lnbits)
                # Docker can assign a new ephemeral host port on restart.
                api.base_url = f"http://{lnbits.get_container_host_ip()}:{lnbits.get_exposed_port(5000)}"
                yield api, provider, relay_url


@pytest.fixture
def wallet_uris(lnbits_backend):
    api, provider, relay_url = lnbits_backend
    sender = register_wallet(api, "Sender", provider, relay_url, credit_sats=1000)
    recipient = register_wallet(api, "Recipient", provider, relay_url)
    return sender, recipient


async def wait_for_provider(sender):
    # HTTP may become ready before the extension subscribes to the relay.
    async with asyncio.timeout(20):
        while True:
            try:
                return await sender.get_info()
            except NWCRelayError:
                await asyncio.sleep(0.25)


async def test_lnbits_invoice_lifecycle(wallet_uris):
    sender_uri, recipient_uri = wallet_uris
    sender = NWCClient(sender_uri, timeout=3)
    recipient = NWCClient(recipient_uri, timeout=10)

    info = await wait_for_provider(sender)
    assert set(METHODS).issubset(info["methods"])
    assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [1_000_000, 0]

    invoice = await recipient.make_invoice(21_000, description="aionwc integration")
    payment_hash = invoice["payment_hash"]
    pending = await recipient.lookup_invoice(payment_hash=payment_hash)
    assert pending["amount"] == 21_000
    assert not pending.get("settled_at")

    payment = await sender.pay_invoice(invoice["invoice"])
    preimage = bytes.fromhex(payment["preimage"])
    assert len(preimage) == 32
    assert hashlib.sha256(preimage).hexdigest() == payment_hash

    settled = await recipient.lookup_invoice(payment_hash=payment_hash)
    assert settled["settled_at"] > 0
    assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [979_000, 21_000]
    transactions = await recipient.list_transactions(transaction_type="incoming")
    assert any(transaction["payment_hash"] == payment_hash for transaction in transactions)


@pytest.mark.parametrize("protocol", ["l402", "mpp", "x402"])
async def test_lnbits_fastapi_payment_round_trip(wallet_uris, protocol):
    from aionwc._payment_wire import decode_json, preimage_hash
    from aionwc.payments import PaymentClient
    from test_http_payments import ApplicationPaymentStore, app_client, paid_app

    sender_uri, recipient_uri = wallet_uris
    sender = NWCClient(sender_uri, timeout=10)
    recipient = NWCClient(recipient_uri, timeout=10)
    await wait_for_provider(sender)
    store = ApplicationPaymentStore()
    app = paid_app(recipient, store, protocol)

    async with app_client(app) as http:
        initial = await http.post("/paid/caf%C3%A9?q=a%2Fb&q=b", json={"work": 1})
        assert initial.status_code == 402 and app.state.served == 0
        challenge = PaymentClient(sender, http).challenge(initial)
        assert challenge.protocol == protocol and challenge.amount_msat == 21_000
        pending = await recipient.lookup_invoice(payment_hash=challenge.payment_hash)
        assert not pending.get("settled_at")
        assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [1_000_000, 0]

        # Exercise automatic detection, payment over NWC, and the authorized retry.
        result = await PaymentClient(sender, http).fetch(
            "POST", "/paid/caf%C3%A9?q=a%2Fb&q=b", json={"work": 1}, max_amount_msat=21_000,
        )
        assert result.response.status_code == 200 and result.credential is not None
        assert result.response.json() == {"name": "café", "amount_msat": 21_000, "body": {"work": 1}}
        assert app.state.served == 1
        assert result.response.headers["cache-control"] == "no-store"
        assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [979_000, 21_000]

        settled_records = []
        for payment in store.payments.values():
            settled = await recipient.lookup_invoice(payment_hash=payment.payment_hash)
            if settled.get("settled_at"):
                settled_records.append(payment)
        assert len(settled_records) == 1
        paid_hash = settled_records[0].payment_hash
        outgoing = await sender.lookup_invoice(payment_hash=paid_hash)
        assert preimage_hash(outgoing["preimage"]) == paid_hash
        assert outgoing["amount"] == 21_000 and outgoing["settled_at"] > 0
        if protocol == "mpp":
            assert decode_json(result.response.headers["Payment-Receipt"], urlsafe=True)["reference"] == paid_hash
        elif protocol == "x402":
            receipt = decode_json(result.response.headers["PAYMENT-RESPONSE"])
            assert receipt["success"] is True and receipt["transaction"] == paid_hash

        # Altered targets cannot spend the same proof on another operation.
        changed = await http.post("/paid/other", json={"work": 1}, headers=result.credential.headers_for(http.base_url))
        assert changed.status_code in {401, 402} and app.state.served == 1
        assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [979_000, 21_000]

        replay = await PaymentClient(sender, http).fetch(
            "POST", "/paid/caf%C3%A9?q=a%2Fb&q=b", json={"work": 1},
            max_amount_msat=21_000, credential=result.credential,
        )
        # L402 tokens can be reused for their scope; charge proofs are single-use.
        assert replay.response.status_code == (200 if protocol == "l402" else 402)
        assert app.state.served == (2 if protocol == "l402" else 1)
        assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [979_000, 21_000]
