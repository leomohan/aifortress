"""
jwt_authenticator.py  —  JWT validation for ML API endpoints
AI Fortress · Chapter 9 · Code Sample 9.A

Validates JWTs for ML inference API requests.

Security controls:
  - Strict algorithm allowlist: only HS256 and RS256 (never 'none')
  - Audience and issuer claim validation
  - Expiry (exp) and not-before (nbf) enforcement
  - Required scope claim enforcement per endpoint
  - Structured AuthResult with principal identity and granted scopes

Does NOT use PyJWT or similar libraries — implements validation
directly using the `cryptography` package to avoid dependency risk.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


_ALLOWED_ALGORITHMS = {"HS256", "RS256"}
_CLOCK_SKEW_SECONDS = 30   # allow 30s clock skew for exp/nbf checks


@dataclass
class AuthResult:
    authenticated: bool
    principal:     str          # subject (sub) claim, or "" on failure
    scopes:        List[str]    # granted scopes from token
    reason:        str          # human-readable result reason
    token_id:      str          # jti claim if present
    expires_at:    int          # Unix timestamp (0 if not present)


class JWTAuthenticationError(ValueError):
    pass


class JWTAuthenticator:
    """
    Validates JWTs for ML API requests.

    Parameters
    ----------
    secret_or_public_key : HMAC secret (bytes) for HS256, or RSA public key
                           PEM (str) for RS256.
    audience             : Expected `aud` claim value.
    issuer               : Expected `iss` claim value.
    required_scopes      : If non-empty, at least one must appear in the token.
    algorithm            : "HS256" (default) or "RS256".
    """

    def __init__(
        self,
        secret_or_public_key: bytes | str,
        audience:             str,
        issuer:               str,
        required_scopes:      Optional[Set[str]] = None,
        algorithm:            str = "HS256",
    ):
        if algorithm not in _ALLOWED_ALGORITHMS:
            raise ValueError(f"Algorithm '{algorithm}' not in allowlist {_ALLOWED_ALGORITHMS}")
        self.key             = secret_or_public_key
        self.audience        = audience
        self.issuer          = issuer
        self.required_scopes = required_scopes or set()
        self.algorithm       = algorithm

    def authenticate(self, token: str) -> AuthResult:
        """
        Validate a JWT token string.
        Returns AuthResult — never raises; errors are captured in `reason`.
        """
        try:
            return self._validate(token)
        except JWTAuthenticationError as e:
            return AuthResult(
                authenticated=False, principal="", scopes=[],
                reason=str(e), token_id="", expires_at=0,
            )
        except Exception as e:
            return AuthResult(
                authenticated=False, principal="", scopes=[],
                reason=f"Unexpected validation error: {e}", token_id="", expires_at=0,
            )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _validate(self, token: str) -> AuthResult:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise JWTAuthenticationError("Malformed JWT: expected 3 dot-separated parts")

        header_b64, payload_b64, sig_b64 = parts

        # 1. Parse and validate header
        header = self._decode_json(header_b64)
        alg    = header.get("alg", "")
        if alg not in _ALLOWED_ALGORITHMS:
            raise JWTAuthenticationError(
                f"Rejected algorithm '{alg}'. Allowed: {sorted(_ALLOWED_ALGORITHMS)}"
            )
        if alg != self.algorithm:
            raise JWTAuthenticationError(
                f"Token uses '{alg}' but authenticator configured for '{self.algorithm}'"
            )

        # 2. Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig_bytes     = self._b64_decode(sig_b64)
        self._verify_signature(alg, signing_input, sig_bytes)

        # 3. Parse payload
        payload = self._decode_json(payload_b64)
        now     = int(time.time())

        # 4. Expiry
        exp = payload.get("exp", 0)
        if exp and now > exp + _CLOCK_SKEW_SECONDS:
            raise JWTAuthenticationError(f"Token expired at {exp} (now={now})")

        # 5. Not-before
        nbf = payload.get("nbf", 0)
        if nbf and now < nbf - _CLOCK_SKEW_SECONDS:
            raise JWTAuthenticationError(f"Token not yet valid (nbf={nbf}, now={now})")

        # 6. Issuer
        if self.issuer and payload.get("iss") != self.issuer:
            raise JWTAuthenticationError(
                f"Issuer mismatch: expected '{self.issuer}', got '{payload.get('iss')}'"
            )

        # 7. Audience
        aud = payload.get("aud", "")
        if isinstance(aud, list):
            if self.audience not in aud:
                raise JWTAuthenticationError(f"Audience '{self.audience}' not in token aud {aud}")
        elif aud != self.audience:
            raise JWTAuthenticationError(
                f"Audience mismatch: expected '{self.audience}', got '{aud}'"
            )

        # 8. Scopes
        scope_str = payload.get("scope", "") or ""
        scopes    = scope_str.split() if scope_str else []
        if self.required_scopes:
            if not self.required_scopes.intersection(set(scopes)):
                raise JWTAuthenticationError(
                    f"Missing required scope. Need one of {sorted(self.required_scopes)}, "
                    f"token has {scopes}"
                )

        return AuthResult(
            authenticated = True,
            principal     = payload.get("sub", ""),
            scopes        = scopes,
            reason        = "OK",
            token_id      = payload.get("jti", ""),
            expires_at    = exp,
        )

    def _verify_signature(self, alg: str, signing_input: bytes, sig: bytes) -> None:
        if alg == "HS256":
            secret = self.key if isinstance(self.key, bytes) else self.key.encode()
            expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, sig):
                raise JWTAuthenticationError("Invalid HMAC-SHA256 signature")
        elif alg == "RS256":
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            pub = load_pem_public_key(
                self.key.encode() if isinstance(self.key, str) else self.key
            )
            try:
                pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            except Exception:
                raise JWTAuthenticationError("Invalid RSA-SHA256 signature")

    @staticmethod
    def _b64_decode(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _decode_json(self, b64: str) -> dict:
        try:
            return json.loads(self._b64_decode(b64))
        except Exception as e:
            raise JWTAuthenticationError(f"Failed to decode JWT part: {e}")

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @classmethod
    def build_hs256_token(
        cls,
        secret:   bytes,
        sub:      str,
        aud:      str,
        iss:      str,
        scope:    str = "",
        ttl:      int = 3600,
        jti:      str = "",
    ) -> str:
        """
        Build a valid HS256 JWT for testing.
        Returns the encoded token string.
        """
        now     = int(time.time())
        header  = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": sub, "aud": aud, "iss": iss,
                   "iat": now, "exp": now + ttl}
        if scope: payload["scope"] = scope
        if jti:   payload["jti"]   = jti

        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        sig   = hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        s_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h_b64}.{p_b64}.{s_b64}"
