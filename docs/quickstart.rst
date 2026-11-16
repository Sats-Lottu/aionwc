Getting started
===============

Use Python 3.11 or later and a wallet that provides a
``nostr+walletconnect://`` connection URI. Give the application access to
``get_info`` and ``get_balance`` to run this example.

Install
-------

Install from PyPI
~~~~~~~~~~~~~~~~~

Choose an installer for a release published on PyPI. Run the Poetry
and uv commands from your application's directory.

.. code-block:: console
   :caption: pip

   python -m pip install aionwc

.. code-block:: console
   :caption: Poetry

   poetry add aionwc

.. code-block:: console
   :caption: uv

   uv add aionwc

Install a local wheel
~~~~~~~~~~~~~~~~~~~~~

Place the built wheel in your application's directory and use the
command for your package manager. Use the filename of the wheel you have.

.. parsed-literal::

   poetry add ./aionwc-|release|-py3-none-any.whl

.. parsed-literal::

   uv add ./aionwc-|release|-py3-none-any.whl

``websockets`` is the required Python dependency. If your wallet uses
NIP-04 and the system lacks OpenSSL AES-256-CBC, install the
``nip04-fallback`` extra. See :doc:`encryption` for the install commands.

Read wallet information and balance
-----------------------------------

Pass the connection URI to the process through ``NWC_URI``. The URI
contains a private key. Keep it out of source control, shell history,
and logs.

Save this example as ``read_wallet.py``.

.. code-block:: python

   import asyncio
   import os

   from aionwc import NWCClient


   async def main():
       wallet = NWCClient(os.environ["NWC_URI"])
       info, balance_msat = await asyncio.gather(
           wallet.get_info(),
           wallet.get_balance(),
       )
       print(info.get("alias", "Lightning wallet"))
       print(f"Balance {balance_msat} msat")


   if __name__ == "__main__":
       asyncio.run(main())

Run the example in the environment used for installation.

- In an activated environment, run ``python read_wallet.py``.
- With Poetry, run ``poetry run python read_wallet.py``.
- With uv, run ``uv run python read_wallet.py``.

The balance is an integer in millisatoshis (1 satoshi = 1,000 millisatoshis).
Each call manages its own WebSocket connection. Independent calls can run
concurrently on the same client.
