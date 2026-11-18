import json

import pytest

from aionwc import NWCProtocolError
from aionwc import _protocol as protocol
from aionwc._encryption import nip44_encrypt
from test_client import WALLET_KEY, WALLET_PUBKEY, make_event, make_uri


def test_signed_event_rejects_unencodable_content_and_changed_id():
    event = make_event(WALLET_KEY, protocol.INFO_KIND, "get_info", [])
    assert protocol.signed_event({**event, "content": "\ud800"}, kind=protocol.INFO_KIND, author=WALLET_PUBKEY) is None
    assert protocol.signed_event({**event, "id": "0" * 64}, kind=protocol.INFO_KIND, author=WALLET_PUBKEY) is None


def test_negotiation_rejects_unsupported_advertised_encryption():
    event = make_event(WALLET_KEY, protocol.INFO_KIND, "get_info", [["encryption", "future"]])
    with pytest.raises(NWCProtocolError, match="no supported encryption"):
        protocol.preferred_encryption(event)


def test_request_encryption_failure_is_protocol_error(monkeypatch):
    from unittest.mock import Mock

    connection = protocol.Connection.from_uri(make_uri("wss://relay.example"))
    monkeypatch.setattr(protocol, "nip44_encrypt", Mock(side_effect=ValueError("invalid key")))
    with pytest.raises(NWCProtocolError, match="Cannot encrypt or sign"):
        protocol.request_event(connection, "get_info", {}, "nip44_v2", 1)


@pytest.mark.parametrize("content,error", [
    ("not-json", "Cannot decode"),
    (json.dumps({"result_type": "get_info", "error": "bad"}), "malformed error"),
    (json.dumps({"result_type": "get_info", "error": {"code": 1, "message": "bad"}}), "malformed error"),
    (json.dumps({"result_type": "get_info", "error": {"code": "bad", "message": 1}}), "malformed error"),
    (json.dumps({"result_type": "get_info", "error": {"code": "bad", "message": "bad"}, "result": {}}), "malformed error"),
    (json.dumps({"result_type": "get_info", "result": []}), "no result object"),
])
def test_malformed_wallet_payloads(content, error):
    connection = protocol.Connection.from_uri(make_uri("wss://relay.example"))
    event = {"content": nip44_encrypt(connection.shared_key, content)}
    with pytest.raises(NWCProtocolError, match=error):
        protocol.response_result(connection, event, "get_info", "nip44_v2")
