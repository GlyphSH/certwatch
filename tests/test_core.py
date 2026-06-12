"""Unit tests for the pure grading logic (no network required)."""

import pytest

from certwatch.core import grade


def g(**kw):
    base = dict(
        days_left=90,
        trusted=True,
        verify_error=None,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        sig_algo="sha256",
        warn_days=30,
    )
    base.update(kw)
    return grade(**base)


def test_healthy_cert_is_A_and_ok():
    letter, status, issues = g()
    assert letter == "A"
    assert status == "OK"
    assert issues == []


def test_expired_is_F_crit():
    letter, status, issues = g(days_left=-5)
    assert letter == "F"
    assert status == "CRIT"
    assert "EXPIRED" in issues[0]


def test_expiring_soon_warns():
    letter, status, issues = g(days_left=9)
    assert status == "WARN"
    assert letter in ("B", "C")
    assert any("expires in 9d" in i for i in issues)


def test_expiring_critical_window():
    _, status, issues = g(days_left=3)
    assert status == "CRIT"
    assert any("expires in 3d" in i for i in issues)


def test_weak_protocol_is_critical():
    letter, status, issues = g(protocol="TLSv1")
    assert status == "CRIT"
    assert any("weak protocol" in i for i in issues)
    assert letter in ("D", "F")


def test_weak_cipher_flagged():
    _, status, issues = g(cipher="ECDHE-RSA-RC4-SHA")
    assert status == "WARN"
    assert "weak cipher" in issues


def test_self_signed_is_F():
    letter, status, issues = g(trusted=False, verify_error="self-signed certificate")
    assert letter == "F"
    assert status == "CRIT"
    assert "self-signed" in issues


def test_untrusted_chain_is_F():
    letter, _, issues = g(trusted=False, verify_error="unable to get local issuer certificate")
    assert letter == "F"
    assert "untrusted chain" in issues


def test_hostname_mismatch_warns_but_not_fatal():
    letter, status, issues = g(trusted=False, verify_error="Hostname mismatch")
    assert "hostname mismatch" in issues
    assert status == "WARN"
    assert letter != "F"


def test_sha1_signature_penalised():
    _, status, issues = g(sig_algo="sha1")
    assert status == "WARN"
    assert any("SHA1" in i for i in issues)


def test_status_never_downgrades_from_crit():
    # weak protocol (CRIT) + expiring soon (WARN) stays CRIT
    _, status, _ = g(protocol="TLSv1.1", days_left=20)
    assert status == "CRIT"


@pytest.mark.parametrize("days,expected_min", [(365, "A"), (20, "B"), (3, "C")])
def test_grade_degrades_with_expiry(days, expected_min):
    letter, _, _ = g(days_left=days)
    assert letter <= expected_min  # 'A' < 'B' < 'C' lexicographically
