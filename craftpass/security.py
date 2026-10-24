"""Password hashing (Argon2id) and TOTP (RFC 6238) primitives."""

from __future__ import annotations

import contextlib
import hmac
import re
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from craftpass.config import Settings

# --------------------------------------------------------------------------
# Credential policy (shared by setup, self-service and admin forms)
# --------------------------------------------------------------------------
_USERNAME_MIN = 3
_USERNAME_MAX = 32
_PASSWORD_MIN = 10
_TOTP_DIGITS = 6
# 3-32 chars, must start and end alphanumeric; dot/dash/underscore inside.
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$")

_WEAK_PASSWORDS = frozenset(
    {
        "password123",
        "password1234",
        "qwerty12345",
        "1234567890",
        "letmein12345",
        "craftpass123",
        "labcraft123",
        "changeme123",
        "admin123456",
        "iloveyou123",
        "welcome12345",
    }
)


def username_problem(value: str) -> str | None:
    """Return a human-readable problem with a proposed username, else None."""
    normalized = (value or "").strip().lower()
    if not _USERNAME_RE.fullmatch(normalized):
        return "3-32 characters; lowercase letters, digits, dot, dash or underscore"
    return None


def password_problem(value: str) -> str | None:
    """Return a human-readable problem with a proposed password, else None."""
    pw = value or ""
    if len(pw) < _PASSWORD_MIN:
        return "at least 10 characters"
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return "a mix of letters and digits"
    if pw.lower() in _WEAK_PASSWORDS:
        return "something less predictable"
    return None


class PasswordService:
    """Argon2id hashing tuned to the OWASP Password Storage Cheat Sheet.

    Startup burns one hash so that verification of a *missing* user can run
    the identical amount of work as a real one (anti user-enumeration).
    """

    def __init__(self, settings: Settings) -> None:
        self._ph = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
        )
        self._dummy = self._ph.hash("craftpass timing equalizer")

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, stored: str, attempt: str) -> bool:
        try:
            return self._ph.verify(stored, attempt)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False

    def equalize_timing(self, attempt: str) -> None:
        """Run a full verification against a throwaway hash.

        Called on the unknown-username path so response timing matches the
        real-username path.
        """
        with contextlib.suppress(VerifyMismatchError, InvalidHashError, VerificationError):
            self._ph.verify(self._dummy, attempt)

    def needs_rehash(self, stored: str) -> bool:
        try:
            return self._ph.check_needs_rehash(stored)
        except InvalidHashError:
            return True


class TotpService:
    """RFC 6238 codes with the standard ±1 step window and replay protection."""

    ISSUER = "CraftPass"
    STEP_SECONDS = 30

    def new_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, secret: str, account: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=self.ISSUER)

    def step_at(self, now: float | None = None) -> int:
        return int((time.time() if now is None else now) // self.STEP_SECONDS)

    def verify(
        self, secret: str, code: str, last_step: int, now: float | None = None
    ) -> int | None:
        """Return the winning timestep, or ``None`` for a bad/stale code.

        Codes are accepted for the previous, current and next step, but a
        step at or before ``last_step`` is rejected (replay protection), and
        a replayed code therefore never advances ``last_step``.
        """
        normalized = (code or "").replace(" ", "")
        if len(normalized) != _TOTP_DIGITS or not normalized.isdigit():
            return None
        totp = pyotp.TOTP(secret)
        base = self.step_at(now)
        for offset in (-1, 0, 1):
            step = base + offset
            if step <= last_step:
                continue
            # pyotp's at() takes a unix timestamp, not a step counter.
            if hmac.compare_digest(totp.at(step * self.STEP_SECONDS), normalized):
                return step
        return None
