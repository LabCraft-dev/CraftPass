"""RS256 signing: session cookies, OIDC tokens and the published JWKS.

One 2048-bit keypair is generated on first boot and persisted under
``DATA_DIR/keys``; the ``kid`` is the first 16 hex chars of the SHA-256
digest of the public key's DER encoding.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import secrets
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from craftpass.config import Settings


class TokenError(Exception):
    """Raised when a token cannot be decoded or fails validation."""


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


class TokenService:
    ALGORITHM = "RS256"
    KEY_BITS = 2048

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._key: rsa.RSAPrivateKey | None = None
        self._kid: str | None = None

    # -- key management ----------------------------------------------------
    def load_or_create(self) -> None:
        path = self._settings.keys_dir / "rs256_private.pem"
        if path.exists():
            self._key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._key = rsa.generate_private_key(public_exponent=65537, key_size=self.KEY_BITS)
            path.write_bytes(
                self._key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
                path.chmod(0o600)
        pub_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = hashlib.sha256(pub_der).hexdigest()[:16]

    @property
    def kid(self) -> str:
        if self._kid is None:
            raise RuntimeError("call load_or_create() before issuing tokens")
        return self._kid

    # -- signing ------------------------------------------------------------
    def _sign(self, claims: dict) -> str:
        return jwt.encode(claims, self._key, algorithm=self.ALGORITHM, headers={"kid": self.kid})

    # -- session tokens (cookie) ---------------------------------------------
    def issue_session(self, user, groups: list[str]) -> str:
        now = int(time.time())
        return self._sign(
            {
                "iss": self._settings.issuer,
                "sub": str(user["id"]),
                "username": user["username"],
                "groups": groups,
                "is_admin": bool(user["is_admin"]),
                "iat": now,
                "exp": now + self._settings.session_ttl_seconds,
                "jti": secrets.token_urlsafe(8),
            }
        )

    def decode_session(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self._key.public_key(),
                algorithms=[self.ALGORITHM],
                issuer=self._settings.issuer,
                options={"require": ["exp", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc

    # -- OIDC tokens -------------------------------------------------------------
    def issue_id_token(
        self, user, groups: list[str], client_id: str, *, nonce: str | None, auth_time: int
    ) -> str:
        now = int(time.time())
        claims: dict = {
            "iss": self._settings.issuer,
            "sub": str(user["id"]),
            "aud": client_id,
            "iat": now,
            "exp": now + self._settings.id_token_ttl,
            "auth_time": auth_time,
            "preferred_username": user["username"],
            "name": user["display_name"] or user["username"],
            "groups": groups,
            "email_verified": False,
        }
        if user["email"]:
            claims["email"] = user["email"]
        if nonce:
            claims["nonce"] = nonce
        return self._sign(claims)

    def issue_access_token(self, user, groups: list[str], client_id: str, scope: str) -> str:
        now = int(time.time())
        return self._sign(
            {
                "iss": self._settings.issuer,
                "sub": str(user["id"]),
                "aud": client_id,
                "iat": now,
                "exp": now + self._settings.access_token_ttl,
                "scope": scope,
                "preferred_username": user["username"],
                "name": user["display_name"] or user["username"],
                "groups": groups,
            }
        )

    def decode_access(self, token: str, client_id: str) -> dict:
        try:
            return jwt.decode(
                token,
                self._key.public_key(),
                algorithms=[self.ALGORITHM],
                audience=client_id,
                issuer=self._settings.issuer,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc

    def decode_any(self, token: str) -> dict:
        """Decode a signed token without audience checks (used by /userinfo)."""
        try:
            return jwt.decode(
                token,
                self._key.public_key(),
                algorithms=[self.ALGORITHM],
                issuer=self._settings.issuer,
                options={"require": ["exp", "iss", "sub"], "verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc

    # -- JWKS ----------------------------------------------------------------------
    def jwks(self) -> dict:
        numbers = self._key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": self.ALGORITHM,
                    "kid": self.kid,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }
