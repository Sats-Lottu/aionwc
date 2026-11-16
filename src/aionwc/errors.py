"""Errors raised by the Nostr Wallet Connect client."""


class NWCError(Exception):
    """Base class for NWC client errors."""


class NWCURIError(NWCError, ValueError):
    """The wallet connection URI is invalid."""


class NWCProtocolError(NWCError):
    """The wallet returned invalid protocol data or the client cannot use a protocol mode."""


class NWCRelayError(NWCError):
    """A relay could not deliver the request or its response.

    :ivar request_id: Signed event ID if the client attempted to publish the request.
    """

    def __init__(self, message: str, *, request_id: str | None = None) -> None:
        self.request_id = request_id
        super().__init__(message)


class NWCTimeoutError(NWCRelayError, TimeoutError):
    """The request deadline passed before the wallet responded."""


class NWCWalletError(NWCError):
    """The wallet returned a NIP-47 error.

    :ivar code: Protocol error code supplied by the wallet.
    :ivar message: Human-readable wallet error message.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
