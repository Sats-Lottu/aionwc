HTTP payments over Lightning
============================

Use ``PaymentClient`` to pay for HTTP resources with a Nostr Wallet Connect
wallet. Use ``PaymentServer`` and the FastAPI dependency ``require_payment``
to charge for an endpoint and run it only after payment is verified.

Install ``pip install 'aionwc[fastapi]>=0.2.0'`` for both
directions. Use ``pip install 'aionwc[payments]>=0.2.0'`` for clients and servers that run
without FastAPI. The base wallet client requires only ``websockets``.

BOLT11 decoding is adapted from ``nwc-agent/scripts/nwc_bolt11.py`` and uses
the existing secp256k1 arithmetic to verify ECDSA signatures and recover the
invoice signing key. Amounts use exact integer millisatoshis. The decoder is
checked against the official BOLT11 invoice vectors.

Supported wire formats
----------------------

* **L402** uses a macaroon and the BOLT11 payment preimage. The client also
  accepts the legacy LSAT scheme name. The server accepts its original
  macaroon and preimage for the same request until expiry.
* **MPP** uses the Lightning ``charge`` intent from
  `draft-lightning-charge-00 <https://paymentauth.org/draft-lightning-charge-00.html>`_.
  The amount must be a whole number of satoshis. The server returns a
  ``Payment-Receipt`` after accepting the single-use proof.
* **x402** implements version 2 ``exact`` on Bitcoin Lightning (``lnbtc``)
  with the ``http:1`` request binding profile. The receiving wallet must
  support creating invoices with a caller-supplied description hash and
  expiry. Settlement verification is local and the server returns
  ``PAYMENT-RESPONSE`` on success. Peers must support the
  `exact Lightning scheme <https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_lnbtc.md>`_.

Pass ``network`` using the BOLT11 prefix after ``ln``. The default ``bc``
works for all three formats. x402 also supports ``tb`` (testnet), and MPP
supports ``bcrt`` (regtest) and ``tbs`` (signet).

Receive payments in FastAPI
---------------------------

The example charges 21 sats for each endpoint. Set ``PUBLIC_ORIGIN`` to the
public scheme, host, and optional port. Configure the server or trusted reverse
proxy to expose that scheme and host to FastAPI. ``NWC_RECEIVER_URI`` belongs
to a wallet connection with permission to create invoices.

.. code-block:: python

   import os

   from fastapi import Depends, FastAPI

   from aionwc import NWCClient
   from aionwc.fastapi import require_payment
   from aionwc.payment_server import PaymentServer, PaymentStore


   def create_app(payment_store: PaymentStore, *, lifespan=None) -> FastAPI:
       app = FastAPI(lifespan=lifespan)
       receiver = PaymentServer(
           NWCClient(os.environ["NWC_RECEIVER_URI"]),
           origin=os.environ["PUBLIC_ORIGIN"],
           store=payment_store,
       )

       @app.get("/report/l402", dependencies=[Depends(require_payment(
           receiver, protocol="l402", amount_msat=21_000,
       ))])
       @app.get("/report/x402", dependencies=[Depends(require_payment(
           receiver, protocol="x402", amount_msat=21_000,
       ))])
       @app.get("/report/mpp", dependencies=[Depends(require_payment(
           receiver, protocol="mpp", amount_msat=21_000,
       ))])
       async def report():
           return {"report": "Paid content"}

       return app

Implement ``PaymentStore`` in your application and pass it to ``create_app``.
The library calls its three asynchronous methods:

* ``save(payment: IssuedPayment) -> bool`` inserts a challenge by payment hash.
  The insertion must be atomic and return ``False`` for an existing hash.
* ``get(payment_hash: str) -> IssuedPayment | None`` returns the original
  challenge. Records remain immutable after insertion.
* ``consume(payment_hash: str) -> bool`` atomically marks an existing, unused
  payment as consumed. Exactly one concurrent call can return ``True``. This
  method is used for MPP and x402.

The application owns the storage implementation, retention, and lifecycle.
Share this state across the application workers that serve the same wallet
and origin. Retain consumed records across restarts for replay protection.
For x402, retain replay entries until at least one hour after
``IssuedPayment.valid_until``, which includes the allowed clock skew. Storage
errors must propagate so a failed state operation prevents resource delivery.
``PaymentServer`` validates the stored challenge, terms, expiry, and proof
before requesting consumption.

Keep invoice issuance behind your usual authentication and rate limits.
With x402, use a receiving node whose invoice signing key is reserved for the
service, as required by the scheme.

The dependency binds the method, target URL including the query string, body,
and configured headers. Supply ``bound_headers`` as a sorted lowercase tuple
of the headers that affect the operation, body interpretation, or account
selection. For example, use ``("authorization", "content-type")`` for an
authenticated MPP POST with JSON. Including ``authorization`` with MPP selects
the separate ``Payment-Authorization`` field. L402 uses ``Authorization`` itself.
Keep application authentication and business idempotency in the application.

To access the receipt in the endpoint, declare a parameter with
``Depends(require_payment(...))``. If the handler returns a custom
``Response`` directly, copy ``receipt.headers`` to that response. An MPP or
x402 proof is consumed before the handler executes. Use the receipt's
``payment_hash`` to correlate settlement with service delivery if the handler
fails. A matching L402 request can reuse its credential until expiry.

Implement PaymentStore with SQLAlchemy
----------------------------------------

This application example uses SQLAlchemy 2.x and SQLite 3.35+ through the
``aiosqlite`` driver. Install these dependencies in the application environment.

.. code-block:: console

   python -m pip install "sqlalchemy[asyncio]>=2.0,<3" aiosqlite

Save the following code as ``payment_store.py`` in your application. Each
operation opens its own session, allowing the same store to serve concurrent
requests. ``save`` uses the primary key to reject duplicate payment hashes.
``consume`` uses a conditional ``UPDATE ... RETURNING`` so only one concurrent
request can consume an unused, unexpired payment. Database errors propagate
to the caller. The transaction commits before either method returns.

.. code-block:: python
   :caption: payment_store.py

   import time
   from dataclasses import asdict

   from sqlalchemy import BigInteger, Boolean, Float, String, Text, false, update
   from sqlalchemy.dialects.sqlite import insert
   from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
   from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

   from aionwc.payment_server import IssuedPayment, PaymentStore
   from aionwc.payments import PaymentProtocol


   class Base(DeclarativeBase):
       pass


   class PaymentRow(Base):
       __tablename__ = "http_payments"

       payment_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
       protocol: Mapped[PaymentProtocol] = mapped_column(String(4))
       scope: Mapped[str] = mapped_column(String(64))
       amount_msat: Mapped[int] = mapped_column(BigInteger)
       expiry_seconds: Mapped[int] = mapped_column(BigInteger)
       valid_until: Mapped[float] = mapped_column(Float)
       accepted: Mapped[str] = mapped_column(Text)
       consumed: Mapped[bool] = mapped_column(Boolean, server_default=false())


   class SQLAlchemyPaymentStore(PaymentStore):
       def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
           self._sessions = sessions

       async def save(self, payment: IssuedPayment) -> bool:
           statement = (
               insert(PaymentRow)
               .values(**asdict(payment))
               .on_conflict_do_nothing(index_elements=[PaymentRow.payment_hash])
               .returning(PaymentRow.payment_hash)
           )
           async with self._sessions.begin() as session:
               result = await session.execute(statement)
               inserted = result.scalar_one_or_none() is not None
           return inserted

       async def get(self, payment_hash: str) -> IssuedPayment | None:
           async with self._sessions() as session:
               row = await session.get(PaymentRow, payment_hash)
               if row is None:
                   return None
               return IssuedPayment(
                   payment_hash=row.payment_hash,
                   protocol=row.protocol,
                   scope=row.scope,
                   amount_msat=row.amount_msat,
                   expiry_seconds=row.expiry_seconds,
                   valid_until=row.valid_until,
                   accepted=row.accepted,
               )

       async def consume(self, payment_hash: str) -> bool:
           statement = (
               update(PaymentRow)
               .where(
                   PaymentRow.payment_hash == payment_hash,
                   PaymentRow.consumed.is_(False),
                   PaymentRow.valid_until > time.time(),
               )
               .values(consumed=True)
               .returning(PaymentRow.payment_hash)
           )
           async with self._sessions.begin() as session:
               result = await session.execute(statement)
               consumed = result.scalar_one_or_none() is not None
           return consumed

Save the earlier ``create_app`` function in ``api.py``. The following
``app.py`` wires the store into that application and manages the engine.
For an existing database, include ``PaymentRow`` in the application's normal
schema migrations. ``create_all`` initializes the tables for this example.

.. code-block:: python
   :caption: app.py

   from contextlib import asynccontextmanager

   from fastapi import FastAPI
   from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

   from api import create_app
   from payment_store import Base, SQLAlchemyPaymentStore

   engine = create_async_engine(
       "sqlite+aiosqlite:///payments.db", connect_args={"timeout": 30},
   )
   sessions = async_sessionmaker(engine, expire_on_commit=False)


   @asynccontextmanager
   async def lifespan(app: FastAPI):
       try:
           async with engine.begin() as connection:
               await connection.run_sync(Base.metadata.create_all)
           yield
       finally:
           await engine.dispose()


   app = create_app(SQLAlchemyPaymentStore(sessions), lifespan=lifespan)

Use the same database file across local workers and keep the retained rows
according to the replay-protection policy above. The application controls
schema migrations, database credentials, and retention.

For PostgreSQL, import ``insert`` from ``sqlalchemy.dialects.postgresql``,
install ``asyncpg``, and configure a ``postgresql+asyncpg://`` engine URL.
The duplicate-handling and consumption statements keep the same structure.
SQLAlchemy documents both the
`asynchronous session lifecycle <https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html>`_
and dialect-specific upserts for
`SQLite <https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#insert-on-conflict-upsert>`_
and `PostgreSQL <https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#insert-on-conflict-upsert>`_.

Pay for a resource
------------------

Use an ``httpx.AsyncClient`` owned by the application. ``NWC_PAYER_URI`` belongs
to a wallet connection with invoice payment permission that returns the
Lightning preimage in the payment result.

.. code-block:: python

   import os

   import httpx

   from aionwc import NWCClient
   from aionwc.payments import PaymentClient


   async def get_report():
       wallet = NWCClient(os.environ["NWC_PAYER_URI"])
       async with httpx.AsyncClient() as http:
           payer = PaymentClient(wallet, http)
           result = await payer.fetch(
               "GET", "https://api.example.com/report/x402", max_amount_msat=21_000,
           )
           result.response.raise_for_status()
           return result.response.json()

On an HTTP 402 response, the default header preference is L402/LSAT, MPP
Lightning charge, then x402 Lightning. Set ``protocol_order`` when constructing
``PaymentClient`` to choose a different preference. This example gives x402
the highest preference within an async function that owns ``wallet`` and ``http``.

.. code-block:: python

   payer = PaymentClient(
       wallet, http, protocol_order=("x402", "mpp", "l402"),
   )

The setting applies to both ``challenge`` and ``fetch``. It accepts a nonempty
tuple or list of unique names from ``l402``, ``mpp``, and ``x402``. ``l402``
also includes the LSAT alias. A shorter sequence limits automatic detection
to those protocols. The client snapshots the sequence when constructed.

If headers supply no supported challenge and ``l402`` is included in the
configured order, detection also accepts a JSON body containing
``{"l402": {"macaroon": "...", "invoice": "..."}}``. The invoice, amount,
expiry, and configured network are validated before payment. Use
``payer.challenge(response).protocol`` to inspect the detected protocol.

``fetch`` makes one paid retry on the same URL. The cap covers the invoice
amount in millisatoshis. Lightning routing fees are controlled separately by
the wallet. Use ``payer.challenge(response)`` to inspect the amount and
``await payer.pay(challenge, max_amount_msat=...)`` to pay after your own
approval or pricing decision. Use HTTPS for network requests that carry
payment credentials.

When a paid retry fails or the wallet drops the connection after publication,
``PaymentInterrupted.challenge`` identifies the invoice and its payment hash.
If the exception has a ``credential``, pass it to ``fetch`` to retry with
the existing proof. Otherwise, inspect the invoice with the wallet's
``lookup_invoice`` and use ``challenge.credential(preimage)`` once the wallet
reports settlement and supplies the preimage. Passing an existing credential
to ``fetch`` uses that proof without automatically paying another invoice.
