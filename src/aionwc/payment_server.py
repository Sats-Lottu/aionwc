"""Require Lightning settlement before serving paid HTTP resources."""

import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ._payment_wire import (
    CLOCK_SKEW, MPP_NETWORKS, NETWORKS, X402_DOMAIN, X402_NETWORKS, PaymentError,
    PaymentProtocol, auth_header, binding_headers, content_digest, decode_invoice, decode_json,
    encode_json, new_macaroon, object_field, origin_of, preimage_hash, request_hash, timestamp,
    x402_invoice,
)
from .client import NWCClient

__all__ = ["IssuedPayment", "PaymentReceipt", "PaymentRequired", "PaymentServer", "PaymentStore"]


@dataclass(frozen=True)
class IssuedPayment:
    """An issued challenge that the application retains for verification."""

    payment_hash: str
    protocol: PaymentProtocol
    scope: str
    amount_msat: int
    expiry_seconds: int
    valid_until: float
    accepted: str


class PaymentStore(Protocol):
    """Application-supplied challenge storage and atomic replay protection.

    Implementations must share state across servers using the same wallet
    and origin. Records are immutable after insertion. Storage failures must
    propagate to the caller.
    """

    async def save(self, payment: IssuedPayment) -> bool:
        """Insert by payment hash atomically, returning False if it already exists."""
        ...

    async def get(self, payment_hash: str) -> IssuedPayment | None:
        """Return the original issued challenge, or None if it is unknown."""
        ...

    async def consume(self, payment_hash: str) -> bool:
        """Atomically mark an existing unused payment used, returning whether it succeeded."""
        ...


class PaymentRequired(Exception):
    """An HTTP response that should be returned before running a paid handler."""

    def __init__(self, headers: dict[str, str], *, status_code: int = 402) -> None:
        self.headers = {"Cache-Control": "no-store", **headers}
        self.status_code = status_code
        super().__init__("Payment required" if status_code == 402 else "Invalid payment credential")


@dataclass(frozen=True)
class PaymentReceipt:
    """The verified payment and the headers to send with the resource."""

    protocol: PaymentProtocol
    payment_hash: str
    amount_msat: int
    headers: dict[str, str]


class PaymentServer:
    """Issue payment challenges and verify proofs with application-supplied state.

    The application provides the store and manages its lifecycle. The wallet
    needs NIP-47 permission to create invoices.
    """

    def __init__(
        self, wallet: NWCClient, *, store: PaymentStore, origin: str, network: str = "bc",
    ) -> None:
        url = httpx.URL(origin)
        self._origin = origin_of(url)
        if url.raw_path != b"/" or network not in NETWORKS:
            raise ValueError("Expected a public HTTP origin and a supported BOLT11 network")
        self.origin = str(url).rstrip("/")
        self._network = network
        self._wallet = wallet
        self._store = store

    async def require_payment(
        self, request: httpx.Request, *, protocol: PaymentProtocol, amount_msat: int,
        description: str = "API access", expiry: int = 300, bound_headers: tuple[str, ...] = (),
    ) -> PaymentReceipt:
        """Verify a paid retry or raise a challenge for a fresh BOLT11 invoice.

        Bind every header that affects the operation, interpretation of the
        body, or account selection. Run application authentication separately.
        """
        if protocol not in {"l402", "mpp", "x402"}:
            raise ValueError("Unknown HTTP payment protocol")
        if type(amount_msat) is not int or amount_msat <= 0:
            raise ValueError("amount_msat must be a positive integer")
        if type(expiry) is not int or expiry <= 0:
            raise ValueError("expiry must be a positive number of seconds")
        if protocol == "mpp" and (amount_msat % 1000 or self._network not in MPP_NETWORKS):
            raise ValueError("MPP Lightning charge needs whole satoshis on mainnet, regtest, or signet")
        if protocol == "x402" and self._network not in X402_NETWORKS:
            raise ValueError("x402 Lightning requires mainnet or testnet")
        if origin_of(request.url) != self._origin:
            raise PaymentError("Request origin does not match the configured public origin")
        names = binding_headers(bound_headers)
        if protocol == "l402" and "authorization" in names:
            raise ValueError("L402 uses the Authorization field for its payment credential")
        domain = X402_DOMAIN if protocol == "x402" else f"aionwc:{protocol}:http:1"
        scope = request_hash(request, names, domain)
        header = _credential_header(protocol, names)
        value = request.headers.get(header)
        if value and (protocol == "x402" or _is_payment_credential(value)):
            receipt = await self._verify(request, protocol, scope, amount_msat, expiry, value)
            if receipt is not None:
                return receipt
            if protocol == "l402":
                raise PaymentRequired({}, status_code=401)
        headers = await self._issue(request, protocol, amount_msat, description, expiry, names, scope)
        raise PaymentRequired(headers)

    async def _issue(
        self, request: httpx.Request, protocol: PaymentProtocol, amount_msat: int,
        description: str, expiry: int, names: tuple[str, ...], scope: str,
    ) -> dict[str, str]:
        if protocol == "x402":
            result = await self._wallet.make_invoice(amount_msat, description_hash=scope, expiry=expiry)
        else:
            result = await self._wallet.make_invoice(amount_msat, description=description, expiry=expiry)
        invoice, details = decode_invoice(result.get("invoice"), self._network)
        if details.amount_msat != amount_msat or result.get("payment_hash", details.payment_hash) != details.payment_hash:
            raise PaymentError("Wallet returned a different invoice amount or payment hash")
        hash_ = details.payment_hash
        valid_until = min(details.expiry_time, details.date + expiry)
        if valid_until <= time.time():
            raise PaymentError("Wallet returned an expired invoice")
        if protocol == "l402":
            accepted = {"macaroon": new_macaroon(hash_)}
            headers = {"WWW-Authenticate": auth_header("L402", {**accepted, "invoice": invoice})}
        elif protocol == "mpp":
            accepted = {
                "id": secrets.token_urlsafe(24), "realm": request.url.raw_host.decode("ascii"), "method": "lightning",
                "intent": "charge", "expires": timestamp(valid_until),
                "request": encode_json({
                    "amount": str(amount_msat // 1000), "currency": "sat", "description": description,
                    "methodDetails": {"invoice": invoice, "network": MPP_NETWORKS[self._network], "paymentHash": hash_},
                }, urlsafe=True),
            }
            if request.content:
                accepted["digest"] = content_digest(request.content)
            if "authorization" in names:
                accepted["header"] = "Payment-Authorization"
            headers = {"WWW-Authenticate": auth_header("Payment", accepted)}
        else:
            accepted = {
                "scheme": "exact", "network": X402_NETWORKS[self._network], "asset": "BTC",
                "amount": str(amount_msat), "payTo": details.payee, "maxTimeoutSeconds": expiry,
                "extra": {
                    "assetTransferMethod": "bolt11", "paymentFlow": "upfront", "invoice": invoice,
                    "requestHash": scope, "requestBindingProfile": "http:1",
                    "requestBindingParams": {"headers": list(names)},
                },
            }
            x402_invoice(accepted, request, self._network)
            valid_until += CLOCK_SKEW
            headers = {"PAYMENT-REQUIRED": encode_json({
                "x402Version": 2, "resource": {"url": str(request.url)}, "accepts": [accepted],
            })}
        payment = IssuedPayment(hash_, protocol, scope, amount_msat, expiry, valid_until, encode_json(accepted))
        if not await self._store.save(payment):
            raise PaymentError("Wallet reused an invoice payment hash")
        return headers

    async def _verify(
        self, request: httpx.Request, protocol: PaymentProtocol, scope: str,
        amount_msat: int, expiry: int, credential: str,
    ) -> PaymentReceipt | None:
        try:
            proof, accepted = _read_credential(protocol, credential, str(request.url))
            hash_ = preimage_hash(proof)
            encoded = encode_json(accepted)
        except (ValueError, RecursionError):
            return None
        if not await self._claim(hash_, protocol, scope, amount_msat, expiry, encoded):
            return None
        headers = {"Cache-Control": "no-store"}
        if protocol == "x402":
            headers["PAYMENT-RESPONSE"] = encode_json({
                "success": True, "network": X402_NETWORKS[self._network], "transaction": hash_,
            })
        if protocol == "mpp":
            headers["Payment-Receipt"] = encode_json({
                "method": "lightning", "challengeId": accepted["id"], "reference": hash_,
                "status": "success", "timestamp": timestamp(time.time()),
            }, urlsafe=True)
        return PaymentReceipt(protocol, hash_, amount_msat, headers)

    async def _claim(
        self, payment_hash: str, protocol: PaymentProtocol, scope: str,
        amount_msat: int, expiry: int, accepted: str,
    ) -> bool:
        payment = await self._store.get(payment_hash)
        if payment is None:
            return False
        if (payment.payment_hash != payment_hash or payment.protocol != protocol or payment.scope != scope
                or payment.amount_msat != amount_msat or payment.expiry_seconds != expiry
                or payment.valid_until <= time.time() or not hmac.compare_digest(payment.accepted, accepted)):
            return False
        if protocol == "l402":
            return True
        return await self._store.consume(payment_hash)


def _credential_header(protocol: PaymentProtocol, names: tuple[str, ...]) -> str:
    if protocol == "x402":
        return "payment-signature"
    if protocol == "mpp" and "authorization" in names:
        return "payment-authorization"
    return "authorization"


def _is_payment_credential(value: str) -> bool:
    return value.split(maxsplit=1)[0].lower() in {"l402", "lsat", "payment"} if value.strip() else False


def _read_credential(
    protocol: PaymentProtocol, value: str, url: str,
) -> tuple[object, dict[str, Any]]:
    if len(value) > 32_768:
        raise PaymentError("Payment credential is too long")
    if protocol == "x402":
        wire = decode_json(value)
        if type(wire.get("x402Version")) is not int or wire["x402Version"] != 2:
            raise PaymentError("Expected an x402 v2 credential")
        if "resource" in wire and object_field(wire["resource"]).get("url") != url:
            raise PaymentError("x402 credential is for a different resource")
        return object_field(wire.get("payload")).get("preimage"), object_field(wire.get("accepted"))
    scheme, _, token = value.partition(" ")
    if protocol == "l402" and scheme.lower() in {"l402", "lsat"}:
        macaroon, separator, proof = token.rpartition(":")
        if separator and macaroon:
            return proof, {"macaroon": macaroon}
    if protocol == "mpp" and scheme.lower() == "payment":
        wire = decode_json(token, urlsafe=True)
        return object_field(wire.get("payload")).get("preimage"), object_field(wire.get("challenge"))
    raise PaymentError("Unexpected payment credential scheme")
