import asyncio
import hashlib
import time
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
NWC_MANIFEST = "https://raw.githubusercontent.com/lnbits/nwcprovider/v1.2.1/manifest.json"
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
    assert release is not None, f"LNbits registry lacks nwcprovider {NWC_PROVIDER_VERSION}"
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


@pytest.fixture
def wallet_uris():
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
                sender = register_wallet(api, "Sender", provider, relay_url, credit_sats=1000)
                recipient = register_wallet(api, "Recipient", provider, relay_url)

            # The extension worker reads provider configuration on startup.
            lnbits.get_wrapped_container().restart(timeout=5)
            readiness.wait_until_ready(lnbits)
            yield sender, recipient


async def test_lnbits_invoice_lifecycle(wallet_uris):
    sender_uri, recipient_uri = wallet_uris
    sender = NWCClient(sender_uri, timeout=3)
    recipient = NWCClient(recipient_uri, timeout=10)

    # HTTP may become ready before the extension subscribes to the relay.
    async with asyncio.timeout(20):
        while True:
            try:
                info = await sender.get_info()
                break
            except NWCRelayError:
                await asyncio.sleep(0.25)

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
    # The NWC provider can return zeroes when the test funding source has no preimage.
    assert preimage == bytes(32) or hashlib.sha256(preimage).hexdigest() == payment_hash

    settled = await recipient.lookup_invoice(payment_hash=payment_hash)
    assert settled["settled_at"] > 0
    assert await asyncio.gather(sender.get_balance(), recipient.get_balance()) == [979_000, 21_000]
    transactions = await recipient.list_transactions(transaction_type="incoming")
    assert any(transaction["payment_hash"] == payment_hash for transaction in transactions)
