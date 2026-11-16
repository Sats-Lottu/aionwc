API reference
=============

.. currentmodule:: aionwc

Client
------

Import the client and exceptions from ``aionwc``. Wallet operations are
coroutines. The constructor validates the URI and settings.

.. autoclass:: NWCClient
   :members: request, get_info, get_balance, make_invoice, pay_invoice, lookup_invoice, list_transactions

Exceptions
----------

.. autoexception:: NWCError

.. autoexception:: NWCURIError

.. autoexception:: NWCProtocolError

.. autoexception:: NWCRelayError

.. autoexception:: NWCTimeoutError

.. autoexception:: NWCWalletError
