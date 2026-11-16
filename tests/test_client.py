import asyncio
import json
from urllib.parse import urlencode

import pytest
from websockets.asyncio.server import serve

from aionwc import NWCClient, NWCProtocolError, NWCTimeoutError, NWCURIError, NWCWalletError
from aionwc._encryption import nip04_decrypt, nip04_encrypt, nip44_decrypt, nip44_encrypt
from aionwc._protocol import create_event, signed_event
from aionwc._secp256k1 import public_key, shared_secret

WALLET_KEY = 3
CLIENT_KEY = 5
WALLET_PUBKEY = public_key(WALLET_KEY).hex()
CLIENT_PUBKEY = public_key(CLIENT_KEY).hex()
SHARED_KEY = shared_secret(WALLET_KEY, bytes.fromhex(CLIENT_PUBKEY))


def make_uri(*relays):
    query = urlencode([("relay", relay) for relay in relays] + [("secret", f"{CLIENT_KEY:064x}")])
    return f"nostr+walletconnect://{WALLET_PUBKEY}?{query}"


def relay_uri(server):
    return f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"


def make_event(secret, kind, content, tags):
    return create_event(secret, public_key(secret).hex(), kind, tags, content)


def test_validates_uri_without_leaking_secret():
    secret = f"{CLIENT_KEY:064x}"
    uri = make_uri("wss://relay.example/ws?token=example")
    assert secret not in repr(NWCClient(uri))
    for invalid in (
        uri.replace("nostr+walletconnect", "https"),
        uri.replace("wss", "https"),
        uri.replace(WALLET_PUBKEY, "0" * 64),
        uri.replace(secret, "0" * 64),
        f"{uri}&secret={secret}",
        f"{uri}#fragment",
    ):
        with pytest.raises(NWCURIError) as error:
            NWCClient(invalid)
        assert secret not in str(error.value)


@pytest.mark.parametrize("encryption", ["nip04", "nip44_v2"])
async def test_signed_encrypted_requests_and_responses(encryption):
    async def handler(socket):
        _, info_subscription, info_filter = json.loads(await socket.recv())
        assert info_filter == {
            "kinds": [13194], "authors": [WALLET_PUBKEY], "limit": 1
        }
        tags = [["encryption", "nip04 nip44_v2"]] if encryption == "nip44_v2" else []
        info = make_event(WALLET_KEY, 13194, "get_balance", tags)
        await socket.send(json.dumps(["EVENT", info_subscription, info]))
        assert json.loads(await socket.recv()) == ["CLOSE", info_subscription]
        _, subscription, filters = json.loads(await socket.recv())
        _, request = json.loads(await socket.recv())
        assert signed_event(request, kind=23194, author=CLIENT_PUBKEY)
        assert ["p", WALLET_PUBKEY] in request["tags"]
        assert filters == {
            "authors": [WALLET_PUBKEY],
            "kinds": [23195],
            "#p": [CLIENT_PUBKEY],
            "#e": [request["id"]],
        }
        if encryption == "nip44_v2":
            assert ["encryption", "nip44_v2"] in request["tags"]
            payload = nip44_decrypt(SHARED_KEY, request["content"])
        else:
            payload = nip04_decrypt(SHARED_KEY, request["content"])
        assert json.loads(payload) == {"method": "get_balance", "params": {}}

        def encrypted_balance(balance):
            result = json.dumps({"result_type": "get_balance", "result": {"balance": balance}})
            if encryption == "nip44_v2":
                return nip44_encrypt(SHARED_KEY, result)
            return nip04_encrypt(SHARED_KEY, result)

        response_tags = [["p", CLIENT_PUBKEY], ["e", request["id"]]]
        wrong_content = encrypted_balance(1)
        forged = make_event(7, 23195, wrong_content, response_tags)
        uncorrelated = make_event(WALLET_KEY, 23195, wrong_content, response_tags[:1])
        wrong_balance = make_event(WALLET_KEY, 23195, wrong_content, response_tags)
        invalid_signature = {**wrong_balance, "sig": "0" * 128}
        for event in (forged, uncorrelated, invalid_signature):
            await socket.send(json.dumps(["EVENT", subscription, event]))
        await socket.send(json.dumps(["EVENT", "another-subscription", wrong_balance]))
        response = make_event(WALLET_KEY, 23195, encrypted_balance(1501), response_tags)
        await socket.send(json.dumps(["EVENT", subscription, response]))

    async with serve(handler, "127.0.0.1", 0) as server:
        nwc = NWCClient(make_uri(relay_uri(server)), timeout=2)
        assert await asyncio.gather(nwc.get_balance(), nwc.get_balance()) == [1501, 1501]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"result_type": "get_balance", "error": {"code": "RESTRICTED", "message": "Denied"}},
         NWCWalletError),
        ({"result_type": "get_info", "result": {}}, NWCProtocolError),
        ({"result_type": "get_balance", "result": {"balance": True}}, NWCProtocolError),
    ],
)
async def test_reports_wallet_and_protocol_errors(payload, expected):
    async def handler(socket):
        _, subscription, _ = json.loads(await socket.recv())
        _, request = json.loads(await socket.recv())
        content = nip04_encrypt(SHARED_KEY, json.dumps(payload))
        tags = [["p", CLIENT_PUBKEY], ["e", request["id"]]]
        response = make_event(WALLET_KEY, 23195, content, tags)
        await socket.send(json.dumps(["EVENT", subscription, response]))

    async with serve(handler, "127.0.0.1", 0) as server:
        nwc = NWCClient(make_uri(relay_uri(server)), encryption="nip04")
        with pytest.raises(expected) as error:
            await nwc.get_balance()
        if isinstance(error.value, NWCWalletError):
            assert error.value.code == "RESTRICTED"


async def test_falls_back_before_publish_and_does_not_replay_after_timeout():
    published = []
    secondary_connections = []

    async def silent_wallet(socket):
        assert json.loads(await socket.recv())[0] == "REQ"
        frame, event = json.loads(await socket.recv())
        assert frame == "EVENT"
        published.append(event["id"])
        await socket.wait_closed()

    async def secondary_wallet(socket):
        secondary_connections.append(True)
        await socket.wait_closed()

    async with (
        serve(silent_wallet, "127.0.0.1", 0) as silent,
        serve(secondary_wallet, "127.0.0.1", 0) as secondary,
    ):
        async with serve(silent_wallet, "127.0.0.1", 0) as closed:
            unreachable = relay_uri(closed)
        uri = make_uri(unreachable, relay_uri(silent), relay_uri(secondary))
        nwc = NWCClient(uri, timeout=1, encryption="nip04")
        with pytest.raises(NWCTimeoutError) as error:
            await nwc.pay_invoice("test-invoice")
    assert published == [error.value.request_id]
    assert not secondary_connections
