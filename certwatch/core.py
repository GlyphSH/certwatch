"""Core TLS inspection and grading logic.

The grading function is deliberately pure (no network) so it can be unit-tested
exhaustively. ``check_host`` handles the network I/O and delegates scoring to it.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509

# Anything below TLS 1.2 is considered broken in 2024+.
WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
# Substrings that mark a negotiated cipher suite as weak.
WEAK_CIPHERS = ("RC4", "3DES", "DES-", "NULL", "MD5", "EXPORT", "ANON")

_RANK = {"OK": 0, "WARN": 1, "CRIT": 2}


def _escalate(current: str, new: str) -> str:
    """Return the more severe of two statuses."""
    return new if _RANK[new] > _RANK[current] else current


@dataclass
class Result:
    """Outcome of inspecting one host."""

    host: str
    port: int
    ok: bool = True  # reachable and certificate parsed
    error: str | None = None
    not_after: datetime | None = None
    days_left: int | None = None
    protocol: str | None = None
    cipher: str | None = None
    trusted: bool = False
    verify_error: str | None = None
    grade: str = "?"
    status: str = "ERROR"  # OK / WARN / CRIT / ERROR
    issues: list[str] = field(default_factory=list)


def grade(
    days_left: int | None,
    trusted: bool,
    verify_error: str | None,
    protocol: str | None,
    cipher: str | None,
    sig_algo: str | None,
    warn_days: int = 30,
) -> tuple[str, str, list[str]]:
    """Score a certificate/connection. Pure function — no I/O.

    Returns ``(letter_grade, status, issues)`` where status is OK/WARN/CRIT.
    """
    issues: list[str] = []
    status = "OK"
    score = 100
    ve = (verify_error or "").lower()

    # Hard failures short-circuit to F.
    if days_left is not None and days_left < 0:
        return "F", "CRIT", [f"EXPIRED {abs(days_left)}d ago"]
    if not trusted:
        if "hostname" in ve or "match" in ve or "subject" in ve:
            # Cert may be perfectly valid, just presented for the wrong name.
            issues.append("hostname mismatch")
            score -= 30
            status = _escalate(status, "WARN")
        elif "self" in ve:
            return "F", "CRIT", ["self-signed"]
        elif "issuer" in ve or "unable to get" in ve:
            return "F", "CRIT", ["untrusted chain"]
        else:
            return "F", "CRIT", [f"untrusted ({verify_error or 'verify failed'})"]

    if protocol in WEAK_PROTOCOLS:
        issues.append(f"weak protocol {protocol}")
        score -= 40
        status = _escalate(status, "CRIT")

    if cipher and any(w in cipher.upper() for w in WEAK_CIPHERS):
        issues.append("weak cipher")
        score -= 30
        status = _escalate(status, "WARN")

    if sig_algo and sig_algo.lower() in ("md5", "sha1"):
        issues.append(f"{sig_algo.upper()} signature")
        score -= 25
        status = _escalate(status, "WARN")

    if days_left is not None:
        if days_left < 7:
            issues.append(f"expires in {days_left}d")
            score -= 30
            status = _escalate(status, "CRIT")
        elif days_left < warn_days:
            issues.append(f"expires in {days_left}d")
            score -= 20
            status = _escalate(status, "WARN")

    letter = (
        "A" if score >= 90
        else "B" if score >= 80
        else "C" if score >= 70
        else "D" if score >= 60
        else "F"
    )
    return letter, status, issues


def _fetch(host: str, port: int, timeout: float):
    """Connect and return (der, protocol, cipher, trusted, verify_error).

    Tries a fully-verified handshake first; on verification failure falls back
    to an unverified one so we can still read and report the certificate.
    """
    ctx = ssl.create_default_context()
    verify_error: str | None = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(True), ss.version(), ss.cipher()[0], True, None
    except ssl.SSLCertVerificationError as exc:
        verify_error = getattr(exc, "verify_message", None) or str(exc)

    uctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock, \
            uctx.wrap_socket(sock, server_hostname=host) as ss:
        return ss.getpeercert(True), ss.version(), ss.cipher()[0], False, verify_error


def check_host(target: str, timeout: float = 8.0, warn_days: int = 30) -> Result:
    """Inspect ``host`` or ``host:port`` (default port 443) and grade it."""
    host, _, port_str = target.strip().partition(":")
    port = int(port_str) if port_str else 443
    result = Result(host=host, port=port)

    try:
        der, proto, cipher, trusted, verr = _fetch(host, port, timeout)
    except socket.gaierror:
        result.ok = False
        result.error = "DNS resolution failed"
        return result
    except (socket.timeout, TimeoutError):
        result.ok = False
        result.error = "connection timed out"
        return result
    except ConnectionRefusedError:
        result.ok = False
        result.error = "connection refused"
        return result
    except ssl.SSLError as exc:
        result.ok = False
        result.error = f"TLS handshake failed: {exc.reason or exc}"
        return result
    except OSError as exc:
        result.ok = False
        result.error = f"connection failed: {exc.__class__.__name__}"
        return result

    cert = x509.load_der_x509_certificate(der)
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None

    result.not_after = not_after
    result.days_left = days_left
    result.protocol = proto
    result.cipher = cipher
    result.trusted = trusted
    result.verify_error = verr
    result.grade, result.status, result.issues = grade(
        days_left, trusted, verr, proto, cipher, sig, warn_days
    )
    return result
