"""Async NIP-47 request and response API."""

import asyncio
import json
import math
import time
from collections.abc import Mapping
from typing import Any, Literal
from uuid import uuid4

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import WebSocketException

from ._protocol import (
    INFO_KIND,
    RESPONSE_KIND,
    Connection,
    Encryption,
    JsonObject,
    preferred_encryption,
    request_event,
    response_result,
    signed_event,
    tag_values,
)
from .errors import NWCProtocolError, NWCRelayError, NWCTimeoutError


async def _send(socket: ClientConnection, *parts: Any) -> None:
    await socket.send(json.dumps(parts, separators=(",", ":")))


async def _receive(socket: ClientConnection) -> list[Any]:
    while True:
        try:
            frame = json.loads(await socket.recv())
        except (ValueError, RecursionError):
            continue
        if isinstance(frame, list) and len(frame) >= 2:
            return frame


async def _negotiate(socket: ClientConnection, wallet: str) -> Encryption:
    subscription = uuid4().hex
    await _send(socket, "REQ", subscription, {"kinds": [INFO_KIND], "authors": [wallet], "limit": 1})
    try:
        async with asyncio.timeout(1.0):
            while True:
                frame = await _receive(socket)
                if frame[1] != subscription:
                    continue
                if frame[0] in ("EOSE", "CLOSED"):
                    return "nip04"
                if frame[0] == "EVENT" and len(frame) == 3:
                    info = await asyncio.to_thread(
                        signed_event, frame[2], kind=INFO_KIND, author=wallet
                    )
                    if info is not None:
                        return preferred_encryption(info)
    except TimeoutError:
        return "nip04"
    finally:
        await _send(socket, "CLOSE", subscription)


class NWCClient:
    """Send async NIP-47 requests using a wallet connection URI.

    Each request owns its WebSocket and can run concurrently with other
    requests. The timeout is a total deadline in seconds, including relay
    connection and encryption discovery.

    :param uri: Wallet-issued connection URI containing the client secret.
    :param timeout: Positive, finite deadline in seconds per operation.
    :param encryption: Select automatically, require NIP-44 v2, or use NIP-04.
    :raises NWCURIError: If the connection URI is invalid.
    :raises ValueError: If the deadline or encryption mode is invalid.
    """

    def __init__(
        self,
        uri: str,
        *,
        timeout: float = 30.0,
        encryption: Literal["auto", "nip04", "nip44_v2"] = "auto",
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        if encryption not in ("auto", "nip04", "nip44_v2"):
            raise ValueError("encryption must be auto, nip04, or nip44_v2")
        self._connection = Connection.from_uri(uri)
        self._timeout = timeout
        self._encryption = encryption

    async def request(
        self, method: str, params: Mapping[str, Any] | None = None
    ) -> JsonObject:
        """Send a NIP-47 command and return its result object.

        :param method: Command supported by the connected wallet.
        :param params: JSON-serializable command arguments.
        :raises NWCWalletError: If the wallet replies with a NIP-47 error.
        :raises NWCProtocolError: If the response is invalid or the encryption mode is unavailable.
        :raises NWCRelayError: If the relay cannot deliver the request or response.
        :raises NWCTimeoutError: If the operation exceeds the deadline.
        """
        if not isinstance(method, str) or not method.strip():
            raise ValueError("method must be a non-empty string")
        arguments = {} if params is None else dict(params)
        connection = self._connection
        wallet = connection.wallet
        client = connection.pubkey
        expires_at = math.ceil(time.time() + self._timeout)
        request_id = None

        try:
            async with asyncio.timeout(self._timeout):
                open_timeout = min(5.0, self._timeout / len(connection.relays))
                for relay in connection.relays:
                    try:
                        async with connect(
                            relay, open_timeout=open_timeout, close_timeout=1
                        ) as socket:
                            encryption = self._encryption
                            if encryption == "auto":
                                encryption = await _negotiate(socket, wallet)

                            event = await asyncio.to_thread(
                                request_event, connection, method, arguments, encryption, expires_at
                            )
                            event_id = event["id"]
                            subscription = uuid4().hex
                            await _send(
                                socket,
                                "REQ",
                                subscription,
                                {
                                    "authors": [wallet],
                                    "kinds": [RESPONSE_KIND],
                                    "#p": [client],
                                    "#e": [event_id],
                                },
                            )
                            # A failed send can still have reached the relay.
                            request_id = event_id
                            await _send(socket, "EVENT", event)
                            return await self._wait_response(
                                socket, subscription, request_id, method, encryption
                            )
                    except (OSError, WebSocketException):
                        if request_id is not None:
                            raise NWCRelayError(
                                "Relay disconnected before the wallet responded",
                                request_id=request_id,
                            ) from None
                raise NWCRelayError("Unable to send the request to any configured relay")
        except TimeoutError:
            raise NWCTimeoutError(
                "Timed out waiting for the wallet response", request_id=request_id
            ) from None

    async def _wait_response(
        self,
        socket: ClientConnection,
        subscription: str,
        request_id: str,
        method: str,
        encryption: Encryption,
    ) -> JsonObject:
        connection = self._connection
        wallet = connection.wallet
        client = connection.pubkey
        while True:
            frame = await _receive(socket)
            if (
                frame[0] == "OK"
                and len(frame) >= 3
                and frame[1] == request_id
                and frame[2] is False
            ):
                raise NWCRelayError("Relay rejected the request", request_id=request_id)
            if frame[0] == "CLOSED" and frame[1] == subscription:
                raise NWCRelayError(
                    "Relay closed the response subscription", request_id=request_id
                )
            if frame[0] != "EVENT" or frame[1] != subscription or len(frame) != 3:
                continue
            event = await asyncio.to_thread(
                signed_event, frame[2], kind=RESPONSE_KIND, author=wallet
            )
            if event is None:
                continue
            if client in tag_values(event, "p") and request_id in tag_values(event, "e"):
                return await asyncio.to_thread(
                    response_result, connection, event, method, encryption
                )

    async def get_info(self) -> JsonObject:
        """Return wallet metadata and supported methods."""
        return await self.request("get_info")

    async def get_balance(self) -> int:
        """Return the wallet balance in millisatoshis."""
        result = await self.request("get_balance")
        balance = result.get("balance")
        if type(balance) is not int or balance < 0:
            raise NWCProtocolError("Wallet response has an invalid balance")
        return balance

    async def make_invoice(
        self,
        amount_msat: int,
        *,
        description: str | None = None,
        description_hash: str | None = None,
        expiry: int | None = None,
    ) -> JsonObject:
        """Create a BOLT11 invoice and return the wallet's result object.

        :param amount_msat: Invoice amount as a positive integer in millisatoshis.
        :param description: Optional invoice description.
        :param description_hash: Optional description hash used in place of a description.
        :param expiry: Optional positive lifetime in seconds.
        """
        if type(amount_msat) is not int or amount_msat <= 0:
            raise ValueError("amount_msat must be a positive integer")
        if description is not None and description_hash is not None:
            raise ValueError("Provide only one of description and description_hash")
        if expiry is not None and (type(expiry) is not int or expiry <= 0):
            raise ValueError("expiry must be a positive number of seconds")
        params: JsonObject = {"amount": amount_msat}
        if description is not None:
            params["description"] = description
        if description_hash is not None:
            params["description_hash"] = description_hash
        if expiry is not None:
            params["expiry"] = expiry
        return await self.request("make_invoice", params)

    async def pay_invoice(
        self, invoice: str, *, amount_msat: int | None = None
    ) -> JsonObject:
        """Pay a BOLT11 invoice and return the wallet's confirmation.

        :param invoice: Recipient's BOLT11 invoice.
        :param amount_msat: Optional positive amount in millisatoshis for an amountless invoice.
        """
        params: JsonObject = {"invoice": invoice}
        if amount_msat is not None:
            if type(amount_msat) is not int or amount_msat <= 0:
                raise ValueError("amount_msat must be a positive integer")
            params["amount"] = amount_msat
        return await self.request("pay_invoice", params)

    async def lookup_invoice(
        self, *, payment_hash: str | None = None, invoice: str | None = None
    ) -> JsonObject:
        """Find an invoice by supplying exactly one of the two identifiers.

        :param payment_hash: Payment hash of the invoice.
        :param invoice: Complete BOLT11 invoice.
        """
        if (payment_hash is None) == (invoice is None):
            raise ValueError("Provide either payment_hash or invoice")
        params = {"payment_hash": payment_hash} if invoice is None else {"invoice": invoice}
        return await self.request("lookup_invoice", params)

    async def list_transactions(
        self,
        *,
        transaction_type: Literal["incoming", "outgoing"] | None = None,
        limit: int | None = None,
        offset: int | None = None,
        from_timestamp: int | None = None,
        until_timestamp: int | None = None,
        unpaid: bool | None = None,
    ) -> list[JsonObject]:
        """List transactions matching optional filters and pagination.

        :param transaction_type: Filter for incoming or outgoing transactions.
        :param limit: Maximum number of records requested.
        :param offset: Number of records to skip.
        :param from_timestamp: Lower time bound as a Unix timestamp in seconds.
        :param until_timestamp: Upper time bound as a Unix timestamp in seconds.
        :param unpaid: Wallet filter for unpaid invoices.
        """
        filters = {
            "type": transaction_type,
            "limit": limit,
            "offset": offset,
            "from": from_timestamp,
            "until": until_timestamp,
            "unpaid": unpaid,
        }
        result = await self.request(
            "list_transactions", {key: value for key, value in filters.items() if value is not None}
        )
        transactions = result.get("transactions")
        if not isinstance(transactions, list) or any(
            not isinstance(item, dict) for item in transactions
        ):
            raise NWCProtocolError("Wallet response has an invalid transaction list")
        return transactions
