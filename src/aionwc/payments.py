"""Pay for HTTP resources with a Lightning wallet over Nostr Wallet Connect."""

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from ._payment_wire import (
    MACAROONS, MPP_NETWORKS, NETWORKS, PaymentError, PaymentProtocol, _unique_fields,
    auth_challenges, content_digest, decimal_amount, decode_invoice, decode_json, encode_json,
    object_field, origin_of, parse_timestamp, preimage_hash, string_field, x402_invoice,
)
from .client import NWCClient
from .errors import NWCProtocolError, NWCRelayError

__all__ = [
    "PaymentChallenge", "PaymentClient", "PaymentCredential", "PaymentError",
    "PaymentInterrupted", "PaymentProtocol", "PaymentResult",
]


@dataclass(frozen=True)
class PaymentCredential:
    """Bearer proof of payment scoped to the origin that issued the challenge."""

    header: str
    value: str = field(repr=False)
    _origin: tuple[str, str, int | None] = field(repr=False)

    def headers_for(self, url: str | httpx.URL) -> dict[str, str]:
        """Return the payment header for an HTTP request to the issuer."""
        if origin_of(httpx.URL(url)) != self._origin:
            raise PaymentError("Payment credential belongs to a different origin")
        return {self.header: self.value}


@dataclass(frozen=True)
class PaymentChallenge:
    """A validated invoice and the wire fields needed to present its preimage."""

    protocol: PaymentProtocol
    invoice: str = field(repr=False)
    payment_hash: str
    amount_msat: int
    expires_at: float
    _network: str = field(repr=False)
    _url: httpx.URL = field(repr=False)
    _header: str = field(repr=False)
    _terms: dict[str, Any] = field(repr=False)

    def credential(self, preimage: str) -> PaymentCredential:
        """Format proof using the preimage from payment or invoice lookup."""
        if preimage_hash(preimage) != self.payment_hash:
            raise PaymentError("Payment preimage does not match the invoice")
        if self.protocol == "l402":
            value = f"{self._terms['scheme']} {self._terms['macaroon']}:{preimage}"
        elif self.protocol == "mpp":
            value = "Payment " + encode_json({
                "challenge": self._terms, "payload": {"preimage": preimage},
            }, urlsafe=True)
        else:
            value = encode_json({
                "x402Version": 2, "accepted": self._terms, "payload": {"preimage": preimage},
            })
        return PaymentCredential(self._header, value, origin_of(self._url))


class PaymentInterrupted(RuntimeError):
    """Payment was attempted or settled before the HTTP flow was interrupted."""

    def __init__(
        self, challenge: PaymentChallenge, credential: PaymentCredential | None = None,
    ) -> None:
        self.challenge = challenge
        self.credential = credential
        super().__init__(f"Payment interrupted for invoice hash {challenge.payment_hash}")


@dataclass(frozen=True)
class PaymentResult:
    """HTTP response and the proof used on the paid request, if any."""

    response: httpx.Response
    credential: PaymentCredential | None = None


class PaymentClient:
    """Read, pay, and retry HTTP 402 challenges with a caller-owned HTTP client.

    :param protocol_order: Unique protocol names in header preference order.
        Defaults to L402, MPP, then x402. A shorter sequence limits detection
        to the listed protocols. L402 JSON bodies are considered after headers.
    """

    def __init__(
        self, wallet: NWCClient, http: httpx.AsyncClient, *, network: str = "bc",
        protocol_order: Sequence[PaymentProtocol] = ("l402", "mpp", "x402"),
    ) -> None:
        if network not in NETWORKS:
            raise ValueError("Unsupported BOLT11 network")
        if not isinstance(protocol_order, Sequence):
            raise ValueError("protocol_order must be an ordered sequence of protocol names")
        order = tuple(protocol_order)
        if (not order or any(protocol not in ("l402", "mpp", "x402") for protocol in order)
                or len(set(order)) != len(order)):
            raise ValueError("protocol_order must contain unique names from l402, mpp, and x402")
        self._wallet = wallet
        self._http = http
        self._network = network
        self._protocol_order = order

    def challenge(self, response: httpx.Response) -> PaymentChallenge:
        """Validate a challenge using the configured protocol preference order.

        A JSON body containing ``l402.invoice`` and ``l402.macaroon`` is also
        accepted when L402 is included and the headers supply no usable challenge.
        """
        if response.status_code != 402:
            raise PaymentError("Expected an HTTP 402 response")
        request = response.request
        origin_of(request.url)
        candidates = auth_challenges(response.headers)
        x402_error = None
        for protocol in self._protocol_order:
            if protocol == "x402":
                if value := response.headers.get("payment-required"):
                    try:
                        return self._x402_challenge(request, value)
                    except PaymentError as error:
                        x402_error = error
                continue
            for scheme, fields in candidates:
                if protocol == "l402" and scheme in {"l402", "lsat"}:
                    return self._l402_challenge(request, scheme, fields)
                if (protocol == "mpp" and scheme == "payment"
                        and fields.get("method") == "lightning" and fields.get("intent") == "charge"):
                    return self._mpp_challenge(request, fields)
        if "l402" in self._protocol_order:
            try:
                body = response.json(object_pairs_hook=_unique_fields)
            except (ValueError, RecursionError, httpx.ResponseNotRead):
                body = None
            if isinstance(body, dict):
                fields = body.get("l402")
                if isinstance(fields, dict) and fields.get("invoice"):
                    return self._l402_challenge(request, "l402", fields)
        if x402_error is not None:
            raise x402_error
        raise PaymentError("No supported Lightning challenge in the HTTP 402 response")

    def _l402_challenge(
        self, request: httpx.Request, scheme: str, fields: Mapping[str, object],
    ) -> PaymentChallenge:
        token = string_field(fields.get("macaroon", fields.get("token")))
        if not MACAROONS.fullmatch(token):
            raise PaymentError("Invalid L402 macaroon")
        invoice, details = decode_invoice(fields.get("invoice"), self._network)
        return PaymentChallenge(
            "l402", invoice, details.payment_hash, int(details.amount_msat), details.expiry_time,
            self._network, request.url, "Authorization", {"scheme": scheme.upper(), "macaroon": token},
        )

    def _mpp_challenge(self, request: httpx.Request, fields: dict[str, str]) -> PaymentChallenge:
        string_field(fields.get("id"))
        string_field(fields.get("realm"))
        payment = decode_json(string_field(fields.get("request")), urlsafe=True)
        method = object_field(payment.get("methodDetails"))
        invoice, details = decode_invoice(method.get("invoice"), self._network)
        header = fields.get("header", "Authorization")
        if "header" in fields and header.lower() != "payment-authorization":
            raise PaymentError("Unsupported MPP credential header")
        if "digest" in fields and fields["digest"] != content_digest(request.content):
            raise PaymentError("MPP challenge does not match the request body")
        if (payment.get("currency") != "sat" or 1000 * decimal_amount(payment.get("amount")) != details.amount_msat
                or MPP_NETWORKS.get(self._network) != method.get("network", "mainnet")
                or method.get("paymentHash", details.payment_hash) != details.payment_hash):
            raise PaymentError("MPP invoice does not match the payment terms")
        expires_at = details.expiry_time
        if "expires" in fields:
            expires_at = min(expires_at, parse_timestamp(fields["expires"]))
        if expires_at <= time.time():
            raise PaymentError("MPP challenge has expired")
        return PaymentChallenge(
            "mpp", invoice, details.payment_hash, int(details.amount_msat), expires_at,
            self._network, request.url, header, fields,
        )

    def _x402_challenge(self, request: httpx.Request, value: str) -> PaymentChallenge:
        payment = decode_json(value)
        accepts = payment.get("accepts")
        if (type(payment.get("x402Version")) is not int or payment["x402Version"] != 2
                or object_field(payment.get("resource")).get("url") != str(request.url)
                or not isinstance(accepts, list)):
            raise PaymentError("Invalid x402 requirements for this resource")
        for accepted in accepts:
            if not isinstance(accepted, dict):
                continue
            try:
                invoice, details = x402_invoice(accepted, request, self._network)
            except PaymentError:
                continue
            return PaymentChallenge(
                "x402", invoice, details.payment_hash, int(details.amount_msat), details.expiry_time,
                self._network, request.url, "PAYMENT-SIGNATURE", accepted,
            )
        raise PaymentError("No valid x402 Lightning invoice for this request")

    async def pay(self, challenge: PaymentChallenge, *, max_amount_msat: int) -> PaymentCredential:
        """Pay a validated challenge once, subject to an invoice-amount limit."""
        if type(max_amount_msat) is not int or max_amount_msat <= 0:
            raise ValueError("max_amount_msat must be a positive integer")
        if challenge._network != self._network or challenge.expires_at <= time.time():
            raise PaymentError("Payment challenge has expired or is on another network")
        _, invoice = decode_invoice(challenge.invoice, self._network)
        if (invoice.payment_hash != challenge.payment_hash or invoice.amount_msat != challenge.amount_msat):
            raise PaymentError("Payment challenge does not match its invoice")
        if invoice.amount_msat > max_amount_msat:
            raise PaymentError("Invoice exceeds max_amount_msat")
        try:
            result = await self._wallet.pay_invoice(challenge.invoice)
            return challenge.credential(result.get("preimage"))
        except NWCRelayError as error:
            if error.request_id is None:
                raise
            raise PaymentInterrupted(challenge) from error
        except (NWCProtocolError, PaymentError) as error:
            raise PaymentInterrupted(challenge) from error

    async def fetch(
        self, method: str, url: str | httpx.URL, *, max_amount_msat: int,
        credential: PaymentCredential | None = None, **request_options: Any,
    ) -> PaymentResult:
        """Make a request and retry at most once after paying a valid HTTP 402 challenge.

        Options are passed to ``httpx.AsyncClient.build_request``. The body must
        be replayable bytes. A supplied credential disables automatic payment.
        """
        request = self._http.build_request(method, url, **request_options)
        origin_of(request.url)
        try:
            request.content
        except httpx.RequestNotRead:
            raise PaymentError("Paid HTTP requests require a replayable body") from None
        if credential is not None:
            request.headers.update(credential.headers_for(request.url))
            response = await self._http.send(request, auth=None, follow_redirects=False)
            return PaymentResult(response, credential)
        response = await self._http.send(request, follow_redirects=False)
        request = response.request
        authorization_scheme = request.headers.get("authorization", "").partition(" ")[0].lower()
        if (response.status_code != 402 or "payment-authorization" in request.headers
                or "payment-signature" in request.headers or authorization_scheme in {"l402", "lsat", "payment"}):
            return PaymentResult(response)
        challenge = self.challenge(response)
        if challenge._header in request.headers:
            raise PaymentError("Payment would overwrite an existing request header")
        paid = await self.pay(challenge, max_amount_msat=max_amount_msat)
        # Rebuild with the same bytes and headers. Preserve the original request
        # and response in the caller's HTTP instrumentation.
        headers = request.headers.copy()
        headers.update(paid.headers_for(request.url))
        retry = httpx.Request(
            request.method, request.url, headers=headers, content=request.content,
            extensions=request.extensions,
        )
        try:
            response = await self._http.send(retry, auth=None, follow_redirects=False)
        except httpx.HTTPError as error:
            raise PaymentInterrupted(challenge, paid) from error
        return PaymentResult(response, paid)
