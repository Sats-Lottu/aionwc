import json
from pathlib import Path

import pytest

from aionwc._bolt11 import parse_invoice

# Official BOLT11 vectors, retained under their CC-BY-4.0 attribution.
# https://github.com/lightning/bolts/blob/master/bolt11/invoice-test.json
# https://github.com/lightning/bolts/blob/master/11-payment-encoding.md#authors
VECTORS = json.loads((Path(__file__).parent / "data" / "bolt11-invoices.json").read_text(encoding="utf-8"))
PAYEE = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
HIGH_S_PAYEE = "02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d"
TEST_PAYEE = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
FIELDS = [("p", bytes.fromhex("11" * 32)), ("s", bytes.fromhex("22" * 32)), ("d", "Test payment")]


@pytest.mark.parametrize("vector", VECTORS, ids=[vector["description"] for vector in VECTORS])
def test_official_bolt11_vectors(vector):
    if vector["valid"]:
        invoice = parse_invoice(vector["invoice"])
        expected_payee = HIGH_S_PAYEE if vector["description"] == "Public-key recovery with high-S signature" else PAYEE
        assert invoice.payee == expected_payee
    else:
        with pytest.raises(ValueError):
            parse_invoice(vector["invoice"])


def test_official_field_values():
    coffee = parse_invoice(VECTORS[1]["invoice"])
    assert coffee.amount_msat == 250_000_000
    assert coffee.date == 1_496_314_658
    assert coffee.expiry == 60
    assert coffee.expiry_time == 1_496_314_718
    assert coffee.description == "1 cup coffee"
    assert coffee.payment_hash == "0001020304050607080900010203040506070809000102030405060708090102"
    assert coffee.payment_secret == "11" * 32
    assert parse_invoice(VECTORS[2]["invoice"]).description == "ナンセンス 1杯"
    hashed = parse_invoice(VECTORS[3]["invoice"])
    assert hashed.description is None
    assert hashed.description_hash == "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"
    assert parse_invoice(VECTORS[10]["invoice"]).amount_msat == 967_878_534


@pytest.mark.parametrize("amount,msat", [
    ("", None), ("1", 100_000_000_000), ("1m", 100_000_000), ("1u", 100_000),
    ("1n", 100), ("10p", 1), ("10000p", 1000),
])
def test_amounts_use_exact_integer_millisatoshis(invoice_factory, amount, msat):
    invoice = parse_invoice(invoice_factory("lnbc" + amount, FIELDS))
    assert invoice.amount_msat == msat
    assert invoice.expiry == 3600


@pytest.mark.parametrize("currency", ["bc", "tb", "tbs", "bcrt"])
def test_supported_invoice_networks(invoice_factory, currency):
    assert parse_invoice(invoice_factory("ln" + currency + "10p", FIELDS)).currency == currency


def test_explicit_signing_key_and_low_s_requirement(invoice_factory):
    explicit = FIELDS + [("n", TEST_PAYEE)]
    assert parse_invoice(invoice_factory("lnbc10p", explicit)).payee == TEST_PAYEE.hex()
    with pytest.raises(ValueError, match="noncanonical"):
        parse_invoice(invoice_factory("lnbc10p", explicit, high_s=True))
    assert parse_invoice(invoice_factory("lnbc10p", FIELDS, high_s=True)).payee == TEST_PAYEE.hex()
    other_key = bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    with pytest.raises(ValueError, match="signature"):
        parse_invoice(invoice_factory("lnbc10p", FIELDS + [("n", other_key)]))


@pytest.mark.parametrize("fields", [
    FIELDS[1:], FIELDS[:1] + FIELDS[2:], FIELDS[:2],
    FIELDS + FIELDS[:1], FIELDS + FIELDS[1:2],
    FIELDS + [("d", "Second description")], FIELDS + [("h", bytes(32))],
    [("p", bytes(31)), *FIELDS[1:]], [("p", [1] * 52), *FIELDS[1:]],
    [*FIELDS[:2], ("d", b"\xff")], FIELDS + [("n", bytes(32))],
])
def test_rejects_invalid_fields_with_valid_checksums_and_signatures(invoice_factory, fields):
    with pytest.raises(ValueError):
        parse_invoice(invoice_factory("lnbc10p", fields))


@pytest.mark.parametrize("amount", ["1p", "19p", "0", "2a"])
def test_rejects_invalid_amounts_before_payment(invoice_factory, amount):
    with pytest.raises(ValueError):
        parse_invoice(invoice_factory("lnbc" + amount, FIELDS))


@pytest.mark.parametrize("signature", [bytes(65), bytes(64) + b"\x04", bytes(64)])
def test_rejects_invalid_signatures(invoice_factory, signature):
    with pytest.raises(ValueError):
        parse_invoice(invoice_factory("lnbc10p", FIELDS, signature=signature))


def test_invalid_bech32_character():
    with pytest.raises(ValueError, match="Bech32 character"):
        parse_invoice("lnbc1bbbbbb")


@pytest.mark.parametrize("words", [[0], [0, 0]])
def test_truncated_tagged_field_header(words):
    from aionwc._bolt11 import _decode_tagged_fields

    with pytest.raises(ValueError, match="Truncated BOLT11 field header"):
        _decode_tagged_fields(words)
