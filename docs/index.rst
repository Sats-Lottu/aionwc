aionwc documentation
====================

``aionwc`` is an asyncio client for Lightning wallets that expose Nostr
Wallet Connect (NIP-47). Connect with a wallet-issued URI to check balances,
create and pay invoices, and look up transactions.

.. code-block:: python

   from aionwc import NWCClient

   # Inside an async function, with a URI supplied by your wallet.
   wallet = NWCClient(uri)
   balance_msat = await wallet.get_balance()

:doc:`quickstart`
   Install the package and make your first request.

:doc:`wallet`
   Create and track invoices, submit payments, and handle uncertain outcomes.

:doc:`payments`
   Pay for HTTP resources or charge for FastAPI endpoints using Lightning.

:doc:`encryption`
   Choose NIP-44 or NIP-04 and see which cryptographic backends the client can use.

:doc:`api`
   Look up public class and method signatures, return values, and errors.

:doc:`development`
   Run tests, generate coverage, and build or publish the documentation.

.. toctree::
   :maxdepth: 2
   :hidden:

   quickstart
   wallet
   payments
   encryption
   api
   development
