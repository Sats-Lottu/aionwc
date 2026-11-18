Development
===========

Tests and coverage
------------------

Install the project with the FastAPI and optional NIP-04 fallback extras to
exercise HTTP payments and both AES backends when OpenSSL is available.
The default test run selects the tests that run without Docker.

.. code-block:: console

   poetry install --extras "nip04-fallback fastapi"
   poetry run pytest --cov=aionwc --cov-report=term-missing --cov-fail-under=100

Integration with LNbits
-----------------------

Start Docker, then install the integration dependencies and run the
integration marker.

.. code-block:: console

   poetry install --with integration --extras "nip04-fallback fastapi"
   poetry run pytest -m integration

Testcontainers starts LNbits and a Nostr relay with fresh wallets for each
test. The suite checks the NWC invoice lifecycle and FastAPI payment flows
for L402, MPP, and x402, including preimages, settlement, balances, request
binding, and replay behavior. Initial setup
requires network access to fetch the container images and the LNbits NWC
Provider extension. The funding source uses simulated funds.

To measure both suites in a single report, clear the default marker
selection.

.. code-block:: console

   poetry run pytest -o addopts= --cov=aionwc --cov-report=term-missing --cov-fail-under=100

GitHub Actions runs the integration suite on pull requests, manual workflow
runs, and releases. Publishing requires both the build with 100% line
coverage and the Docker integration job to pass.

Build the documentation
-----------------------

The documentation dependencies are in Poetry's optional ``docs`` group.
Sphinx imports the installed package to generate the API reference.

.. code-block:: console

   poetry install --with docs
   poetry run sphinx-build -M html docs docs/_build -W --keep-going

Open ``docs/_build/html/index.html`` for a local preview. To use the
site search, serve the generated files over HTTP.

.. code-block:: console

   poetry run python -m http.server --bind 127.0.0.1 --directory docs/_build/html 8000

Visit `http://127.0.0.1:8000 <http://127.0.0.1:8000>`_ while the server runs.

Read the Docs Community
-----------------------

The repository's ``.readthedocs.yaml`` installs the package and the
locked documentation dependencies with Poetry, then builds the Sphinx
site with warnings treated as errors.

The ``Documentation`` entry in ``[project.urls]`` points to the
`public documentation site <https://aionwc.readthedocs.io/>`_.
