"""Wire formats for HTTP payments backed by BOLT11 invoices."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.request import parse_http_list, parse_keqv_list

from httpx import Headers, Request, URL

from ._bolt11 import Invoice, parse_invoice

PaymentProtocol = Literal["l402", "x402", "mpp"]
X402_NETWORKS = {
    "bc": "lnbtc:000000000019d6689c085ae165831e93",
    "tb": "lnbtc:000000000933ea01ad0ee984209779ba",
}
MPP_NETWORKS = {"bc": "mainnet", "bcrt": "regtest", "tbs": "signet"}
NETWORKS = X402_NETWORKS.keys() | MPP_NETWORKS.keys()
HEX_32 = re.compile(r"[0-9a-f]{64}")
MACAROONS = re.compile(r"[A-Za-z0-9+/_-]+={0,2}(?:,[A-Za-z0-9+/_-]+={0,2})*")
CLOCK_SKEW = 60


class PaymentError(ValueError):
    """An HTTP payment challenge, invoice, or credential is invalid."""


def origin_of(url: URL) -> tuple[str, str, int | None]:
    if url.scheme not in {"http", "https"} or not url.host or url.userinfo or url.fragment:
        raise PaymentError("Expected an absolute HTTP URL without user information or a fragment")
    return url.scheme, url.host, url.port


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_digest(data: bytes) -> str:
    value = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return f"sha-256=:{value}:"


def json_bytes(data: object) -> bytes:
    # The signed binding and MPP fields use ASCII keys and contain no JSON numbers.
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


def encode_json(data: object, *, urlsafe: bool = False) -> str:
    raw = json_bytes(data)
    if urlsafe:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return base64.b64encode(raw).decode("ascii")


def decode_json(value: str, *, urlsafe: bool = False) -> dict[str, Any]:
    if len(value) > 32_768:
        raise PaymentError("Payment header is too long")
    alphabet = rb"[A-Za-z0-9_-]+={0,2}" if urlsafe else rb"[A-Za-z0-9+/]+={0,2}"
    try:
        raw = value.encode("ascii")
        if not re.fullmatch(alphabet, raw):
            raise ValueError
        if urlsafe:
            raw += b"=" * (-len(raw) % 4)
        payload = json.loads(
            base64.b64decode(raw, altchars=b"-_" if urlsafe else None, validate=True),
            object_pairs_hook=_unique_fields,
        )
    except (ValueError, RecursionError):
        raise PaymentError("Malformed payment header") from None
    return object_field(payload)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Repeated JSON field")
    return result


def object_field(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PaymentError("Expected a JSON object in payment header")
    return value


def string_field(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError("Missing payment header field")
    return value


def decimal_amount(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,19}", value) or int(value) <= 0:
        raise PaymentError("Expected a positive decimal payment amount")
    return int(value)


def preimage_hash(value: object) -> str:
    if not isinstance(value, str) or not HEX_32.fullmatch(value):
        raise PaymentError("Expected a 32-byte Lightning payment preimage")
    return digest(bytes.fromhex(value))


def decode_invoice(value: object, network: str) -> tuple[str, Invoice]:
    invoice = string_field(value)
    try:
        details = parse_invoice(invoice)
        payment_hash = details.payment_hash
    except ValueError:
        raise PaymentError("Invalid BOLT11 invoice") from None
    now = time.time()
    if (details.currency != network or not details.amount_msat or details.expiry <= 0
            or not HEX_32.fullmatch(payment_hash) or details.date > now + CLOCK_SKEW
            or details.expiry_time <= now):
        raise PaymentError("Invalid amount, date, or network in BOLT11 invoice")
    return invoice, details


def timestamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: str) -> float:
    try:
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value):
            raise ValueError
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, OverflowError, OSError):
        raise PaymentError("Invalid payment expiration timestamp") from None


def auth_challenges(headers: Headers) -> list[tuple[str, dict[str, str]]]:
    """Split WWW-Authenticate fields, keeping a scheme's auth-params together."""
    groups: list[tuple[str, list[str]]] = []
    for field in headers.get_list("www-authenticate"):
        if len(field) > 32_768:
            continue
        group: list[str] = []
        for item in parse_http_list(field):
            if match := re.fullmatch(r"([\w-]+)\s+([^=\s].*)", item):
                scheme, first = match.groups()
                group = [first]
                groups.append((scheme.lower(), group))
            elif "=" in item:
                group.append(item)
    result = []
    for scheme, params in groups:
        if scheme in {"l402", "lsat", "payment"} and all("=" in item for item in params):
            parsed = parse_keqv_list(params)
            fields = {key.strip().lower(): value for key, value in parsed.items()}
            if len(fields) == len(params):
                result.append((scheme, fields))
    return result


def auth_header(scheme: str, fields: dict[str, str]) -> str:
    return scheme + " " + ", ".join(f'{key}="{value}"' for key, value in fields.items())


def new_macaroon(payment_hash: str) -> str:
    """Mint a caveat-free L402 V2 macaroon for exact-token verification by its issuer."""
    identifier = b"\x00\x00" + bytes.fromhex(payment_hash) + secrets.token_bytes(32)
    signature = hmac.digest(secrets.token_bytes(32), identifier, "sha256")
    # Fixed-length fields need only a single varint byte each. The two zero
    # markers end the header and the caveat list in the macaroon V2 format.
    binary = b"\x02\x02\x42" + identifier + b"\x00\x00\x06\x20" + signature
    return base64.b64encode(binary).decode("ascii")


def binding_headers(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]+", name)
        and name not in {"payment-signature", "payment-authorization"} for name in value
    ) or list(value) != sorted(set(value)):
        raise PaymentError("Bound headers must be unique, lowercase, and sorted")
    return tuple(value)


def request_hash(request: Request, names: tuple[str, ...], domain: str) -> str:
    hashed_headers = []
    for name in names:
        values = request.headers.get_list(name)
        try:
            value = ", ".join(item.strip(" \t") for item in values).encode("ascii")
        except UnicodeEncodeError:
            raise PaymentError("Bound header values must be ASCII") from None
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise PaymentError("Invalid bound header value")
        hashed_headers.append({"name": name, "valueHash": digest(b"\x01" + value if values else b"\x00")})
    return digest(json_bytes({
        "domain": domain, "method": request.method, "url": str(request.url),
        "bodyHash": digest(request.content), "headers": hashed_headers,
    }))


X402_DOMAIN = "x402:exact:lnbtc:bolt11:http:1"


def x402_invoice(
    accepted: dict[str, Any], request: Request, network: str,
) -> tuple[str, Invoice]:
    extra = object_field(accepted.get("extra"))
    params = object_field(extra.get("requestBindingParams"))
    if (accepted.get("scheme") != "exact" or accepted.get("network") != X402_NETWORKS.get(network)
            or network not in X402_NETWORKS or accepted.get("asset") != "BTC"
            or extra.get("assetTransferMethod", "bolt11") != "bolt11"
            or extra.get("paymentFlow") != "upfront" or extra.get("requestBindingProfile") != "http:1"
            or set(params) != {"headers"}):
        raise PaymentError("Unsupported x402 payment scheme or request binding")
    expected_hash = request_hash(request, binding_headers(params["headers"]), X402_DOMAIN)
    invoice, details = decode_invoice(extra.get("invoice"), network)
    timeout = accepted.get("maxTimeoutSeconds")
    if (decimal_amount(accepted.get("amount")) != details.amount_msat
            or type(timeout) is not int or timeout != details.expiry
            or details.payee != accepted.get("payTo") or not details.payee
            or not re.fullmatch(r"0[23][0-9a-f]{64}", details.payee)
            or expected_hash != extra.get("requestHash") or expected_hash != details.description_hash):
        raise PaymentError("x402 invoice does not match the request or payment terms")
    return invoice, details
