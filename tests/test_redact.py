from app import redact
from attacks.corpus import AADHAAR, AADHAAR_FMT


def test_verhoeff_known_vector_and_generated_aadhaar():
    assert redact.verhoeff_valid("2363")
    assert not redact.verhoeff_valid("2364")
    assert redact.verhoeff_valid(AADHAAR)


def test_luhn():
    assert redact.luhn_valid("4111111111111111")
    assert not redact.luhn_valid("4111111111111112")


def test_valid_aadhaar_redacted_invalid_left_alone():
    assert "[REDACTED_AADHAAR]" in redact.redact(f"id {AADHAAR_FMT}").text
    invalid = "2345 6789 0125"
    assert redact.redact(f"id {invalid}").counts.get("aadhaar") is None


def test_card_requires_luhn():
    assert redact.redact("4111 1111 1111 1111").counts == {"card": 1}
    assert "card" not in redact.redact("4111 1111 1111 1112").counts


def test_pan_requires_valid_holder_type():
    assert redact.redact("PAN ABCPE1234F").counts == {"pan": 1}
    assert "pan" not in redact.redact("PAN ABCDE1234F").counts


def test_phones_email_and_secrets():
    r = redact.redact("Call +91 98290 12345 or 98290 12345 or (415) 555-0132 or +44 7911 123456, mail raj@example.com")
    assert r.counts["phone"] == 4 and r.counts["email"] == 1
    assert redact.redact("AKIAIOSFODNN7EXAMPLE").counts == {"cloud_key": 1}
    assert "token" in redact.redact("ghp_" + "a" * 36).counts
    assert "secret" in redact.redact("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").counts
    assert "secret" in redact.redact("password = hunter2hunter2").counts
    assert "private_key" in redact.redact("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----").counts


def test_git_sha_and_plain_numbers_are_not_secrets():
    assert redact.redact("commit 3f786850e387550fdab836ed7e6dc881de23001b").counts == {}
    assert redact.redact("Order 1234567890 shipped on 2026-11-21").counts == {}


def test_canary_always_redacted():
    assert redact.redact("ref AEGIS-CANARY-AB12CD34").counts == {"canary": 1}
