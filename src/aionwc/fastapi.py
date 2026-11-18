"""FastAPI dependencies for paid endpoints. Install the ``fastapi`` extra."""

from collections.abc import Awaitable, Callable

import httpx
from fastapi import HTTPException, Request, Response

from ._payment_wire import PaymentError, PaymentProtocol, binding_headers, origin_of
from .payment_server import PaymentReceipt, PaymentRequired, PaymentServer

__all__ = ["require_payment"]


def require_payment(
    server: PaymentServer, *, protocol: PaymentProtocol, amount_msat: int,
    description: str = "API access", expiry: int = 300, bound_headers: tuple[str, ...] = (),
) -> Callable[[Request, Response], Awaitable[PaymentReceipt]]:
    """Create a dependency that challenges or admits a request before the endpoint runs."""
    names = binding_headers(bound_headers)

    async def authorize(request: Request, response: Response) -> PaymentReceipt:
        try:
            url = httpx.URL(str(request.url))
            if origin_of(url) != origin_of(httpx.URL(server.origin)):
                raise PaymentError("Unexpected request origin")
            # Starlette's URL uses the decoded path. Bind the original target,
            # including percent escapes and query ordering, whenever ASGI supplies it.
            if "raw_path" in request.scope:
                target = request.scope["raw_path"].decode("ascii")
                if query := request.scope.get("query_string"):
                    target += "?" + query.decode("ascii")
                url = httpx.URL(server.origin + target)
            incoming = httpx.Request(
                request.method, url, headers=request.headers.raw, content=await request.body(),
            )
        except (PaymentError, UnicodeError, httpx.InvalidURL) as error:
            raise HTTPException(400, "Invalid payment request target") from error
        try:
            receipt = await server.require_payment(
                incoming, protocol=protocol, amount_msat=amount_msat,
                description=description, expiry=expiry, bound_headers=names,
            )
        except PaymentRequired as error:
            raise HTTPException(error.status_code, str(error), headers=error.headers) from error
        response.headers.update(receipt.headers)
        return receipt

    return authorize
