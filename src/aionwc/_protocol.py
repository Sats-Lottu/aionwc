"""NIP-47 event and payload handling adapted from nwc-agent's nwc_wallet.py."""

import json
import re
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Literal, TypedDict, cast
from urllib.parse import parse_qs, urlsplit

from ._encryption import nip04_decrypt, nip04_encrypt, nip44_decrypt, nip44_encrypt
from ._secp256k1 import public_key, schnorr_sign, schnorr_verify, shared_secret
from .errors import NWCProtocolError, NWCURIError, NWCWalletError

INFO_KIND = 13194
REQUEST_KIND = 23194
RESPONSE_KIND = 23195
Encryption = Literal["nip04", "nip44_v2"]
JsonObject = dict[str, Any]
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}")
_HEX_SIGNATURE = re.compile(r"[0-9a-f]{128}")


class Event(TypedDict):
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    sig: str


def _valid_relay(url: str) -> bool:
    parsed = urlsplit(url)
    return (
        parsed.scheme in {"ws", "wss"}
        and bool(parsed.hostname)
        and parsed.port != 0
        and parsed.username is None
        and "#" not in url
        and not any(character.isspace() or ord(character) < 32 for character in url)
    )


@dataclass(frozen=True)
class Connection:
    wallet: str
    pubkey: str
    secret: int = field(repr=False)
    shared_key: bytes = field(repr=False)
    relays: tuple[str, ...] = field(repr=False)

    @classmethod
    def from_uri(cls, uri: str) -> "Connection":
        try:
            parsed = urlsplit(uri)
            params = parse_qs(parsed.query, keep_blank_values=True)
            secrets = params.get("secret", [])
            relays = tuple(dict.fromkeys(params.get("relay", [])))
            if (
                parsed.scheme != "nostr+walletconnect"
                or parsed.path not in {"", "/"}
                or "#" in uri
                or not _HEX_KEY.fullmatch(parsed.netloc)
                or len(secrets) != 1
                or not _HEX_KEY.fullmatch(secrets[0])
                or not relays
                or not all(_valid_relay(relay) for relay in relays)
            ):
                raise ValueError
            wallet = parsed.netloc.lower()
            secret = int(secrets[0], 16)
            shared_key = shared_secret(secret, bytes.fromhex(wallet))
            return cls(wallet, public_key(secret).hex(), secret, shared_key, relays)
        except ValueError:
            raise NWCURIError("Invalid Nostr Wallet Connect URI") from None


def _event_id(
    pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str
) -> bytes:
    event = [0, pubkey, created_at, kind, tags, content]
    encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode()
    return sha256(encoded).digest()


def create_event(
    secret: int, pubkey: str, kind: int, tags: list[list[str]], content: str
) -> Event:
    created_at = int(time.time())
    event_id = _event_id(pubkey, created_at, kind, tags, content)
    return Event(
        id=event_id.hex(),
        pubkey=pubkey,
        created_at=created_at,
        kind=kind,
        tags=tags,
        content=content,
        sig=schnorr_sign(secret, event_id).hex(),
    )


def signed_event(data: Any, *, kind: int, author: str) -> Event | None:
    if (
        not isinstance(data, dict)
        or type(data.get("kind")) is not int
        or data.get("kind") != kind
        or data.get("pubkey") != author
        or type(data.get("created_at")) is not int
        or not isinstance(data.get("content"), str)
        or not isinstance(data.get("tags"), list)
        or not isinstance(data.get("sig"), str)
        or not _HEX_SIGNATURE.fullmatch(data["sig"])
        or any(
            not isinstance(tag, list) or any(not isinstance(value, str) for value in tag)
            for tag in data["tags"]
        )
    ):
        return None
    try:
        actual_id = _event_id(author, data["created_at"], kind, data["tags"], data["content"])
    except UnicodeError:
        return None
    if data.get("id") != actual_id.hex():
        return None
    if not schnorr_verify(bytes.fromhex(author), actual_id, bytes.fromhex(data["sig"])):
        return None
    return cast(Event, data)


def tag_values(event: Event, name: str) -> set[str]:
    return {tag[1] for tag in event["tags"] if len(tag) >= 2 and tag[0] == name}


def preferred_encryption(info: Event) -> Encryption:
    advertised = tag_values(info, "encryption")
    schemes = {scheme for tag in advertised for scheme in tag.split()}
    if "nip44_v2" in schemes:
        return "nip44_v2"
    if not advertised or "nip04" in schemes:
        return "nip04"
    raise NWCProtocolError("Wallet advertises no supported encryption")


def request_event(
    connection: Connection,
    method: str,
    params: JsonObject,
    encryption: Encryption,
    expires_at: int,
) -> Event:
    plaintext = json.dumps({"method": method, "params": params}, allow_nan=False)
    tags = [["p", connection.wallet], ["expiration", str(expires_at)]]
    try:
        if encryption == "nip44_v2":
            content = nip44_encrypt(connection.shared_key, plaintext)
            tags.append(["encryption", encryption])
        else:
            content = nip04_encrypt(connection.shared_key, plaintext)
        return create_event(connection.secret, connection.pubkey, REQUEST_KIND, tags, content)
    except ValueError:
        raise NWCProtocolError("Cannot encrypt or sign the wallet request") from None


def response_result(
    connection: Connection,
    event: Event,
    method: str,
    encryption: Encryption,
) -> JsonObject:
    decrypt = nip44_decrypt if encryption == "nip44_v2" else nip04_decrypt
    try:
        payload = json.loads(decrypt(connection.shared_key, event["content"]))
    except (ValueError, RecursionError):
        raise NWCProtocolError("Cannot decode the wallet response") from None

    if not isinstance(payload, dict) or payload.get("result_type") != method:
        raise NWCProtocolError("Wallet response has an unexpected result type")
    error = payload.get("error")
    result = payload.get("result")
    if error is not None:
        if (
            result is not None
            or not isinstance(error, dict)
            or not isinstance(error.get("code"), str)
            or not isinstance(error.get("message"), str)
        ):
            raise NWCProtocolError("Wallet response has a malformed error")
        raise NWCWalletError(error["code"], error["message"])
    if not isinstance(result, dict):
        raise NWCProtocolError("Wallet response has no result object")
    return result
