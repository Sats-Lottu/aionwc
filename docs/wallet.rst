Wallet operations
=================

Wallets can limit a connection to specific methods. Use
:meth:`aionwc.NWCClient.get_info` to inspect the methods reported by your
wallet and grant the connection the permissions your application needs.

Create and look up an invoice
-----------------------------

Pass the amount in millisatoshis. This example creates a 21-satoshi BOLT11
invoice and reads back its status by payment hash.

.. code-block:: python

   from aionwc import NWCClient


   async def create_example_invoice(wallet: NWCClient):
       invoice = await wallet.make_invoice(
           21_000,
           description="Example invoice",
           expiry=300,
       )
       status = await wallet.lookup_invoice(payment_hash=invoice["payment_hash"])
       return invoice["invoice"], status

The result fields depend on the wallet. You can also look up an invoice
using ``lookup_invoice(invoice=bolt11)``.

Pay an invoice
--------------

Call ``await wallet.pay_invoice(bolt11)`` to ask the wallet to pay a BOLT11
invoice. Pass ``amount_msat`` when the invoice leaves the amount unspecified.
On success, the method returns the wallet's result dictionary.

If the relay disconnects or a timeout occurs after a publication
attempt, the payment may have been processed. Check its status with
``lookup_invoice`` before deciding whether to try again.
:exc:`aionwc.NWCRelayError` and :exc:`aionwc.NWCTimeoutError` expose
``request_id`` when publication was attempted. This is the Nostr event ID.
Use the invoice or its payment hash to query payment status.

List transactions
-----------------

Use ``transaction_type="incoming"`` or ``transaction_type="outgoing"``
to filter by direction. For example, inside an async function, call
``await wallet.list_transactions(transaction_type="incoming", limit=10)``.
The method also accepts an offset, Unix timestamp bounds in seconds, and an
``unpaid`` filter. The wallet determines which optional filters it supports.

Handle errors
-------------

Use :exc:`aionwc.NWCWalletError` to read a rejection from the wallet.
Its ``code`` and ``message`` attributes contain the NIP-47 error.
See :doc:`api` for the other public exceptions.
