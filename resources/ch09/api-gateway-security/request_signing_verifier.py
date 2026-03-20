"""
request_signing_verifier.py  —  HMAC-SHA256 request signature verification
AI Fortress · Chapter 9 · Code Sample 9.A

Verifies that ML API requests are signed by the expected client, protecting
against replay attacks and request tampering.

Signing scheme:
  HMAC-SHA256( key,
    method.upper() + "\n" +
    path           + "\n" +
    timestamp      + "\n" +
    body_sha256
  )

Headers required on every signed request:
  X-AF-Timestamp  : Unix timestamp (seconds) as a string
  X-AF-Signature  : hex HMAC-SHA256 of the signing string
  X-AF-Key-Id     : key identifier (for key lookup)

Replay window: 300 seconds (5 minutes)
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Dict, Optional


REPLAY_WINDOW_SECONDS = 300


@dataclass
class SigningVerifyResult:
    valid:   bool
    key_id:  str
    reason:  str


class RequestSigningVerifier:
    """
    Verifies HMAC-SHA256 signed API requests.

    Parameters
    ----------
    signing_keys : Dict of {key_id: secret_bytes}.
    """

    def __init__(self, signing_keys: Dict[str, bytes]):
        self._keys = signing_keys

    def verify(
        self,
        method:    str,
        path:      str,
        timestamp: str,
        signature: str,
        body:      bytes = b"",
        key_id:    str   = "",
        now:       Optional[int] = None,
    ) -> SigningVerifyResult:
        """
        Verify a signed request.

        Parameters
        ----------
        method    : HTTP method ("POST", "GET", etc.)
        path      : Request path ("/v1/predict")
        timestamp : X-AF-Timestamp header value (Unix seconds string)
        signature : X-AF-Signature header value (hex HMAC-SHA256)
        body      : Raw request body bytes
        key_id    : X-AF-Key-Id header value
        now       : Override current time (for testing)
        """
        current = now if now is not None else int(time.time())

        # 1. Timestamp parse
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            return SigningVerifyResult(False, key_id, "Invalid or missing timestamp")

        # 2. Replay window check
        if abs(current - ts) > REPLAY_WINDOW_SECONDS:
            return SigningVerifyResult(
                False, key_id,
                f"Timestamp outside replay window ({REPLAY_WINDOW_SECONDS}s). "
                f"Request ts={ts}, server ts={current}"
            )

        # 3. Key lookup
        secret = self._keys.get(key_id)
        if secret is None:
            return SigningVerifyResult(False, key_id, f"Unknown key_id '{key_id}'")

        # 4. Reconstruct signing string
        body_hash     = hashlib.sha256(body).hexdigest()
        signing_str   = "\n".join([method.upper(), path, timestamp, body_hash]).encode()

        # 5. Compute expected signature (constant-time comparison)
        expected = hmac.new(secret, signing_str, hashlib.sha256).hexdigest()
        try:
            sig_bytes      = bytes.fromhex(signature)
            expected_bytes = bytes.fromhex(expected)
        except ValueError:
            return SigningVerifyResult(False, key_id, "Signature is not valid hex")

        if not hmac.compare_digest(sig_bytes, expected_bytes):
            return SigningVerifyResult(False, key_id, "Signature mismatch")

        return SigningVerifyResult(True, key_id, "OK")

    @staticmethod
    def sign_request(
        secret:    bytes,
        key_id:    str,
        method:    str,
        path:      str,
        body:      bytes = b"",
        timestamp: Optional[int] = None,
    ) -> Dict[str, str]:
        """
        Helper: generate the signed headers for a request.
        Returns a dict of headers to add to the outgoing request.
        """
        ts        = str(timestamp or int(time.time()))
        body_hash = hashlib.sha256(body).hexdigest()
        signing   = "\n".join([method.upper(), path, ts, body_hash]).encode()
        sig       = hmac.new(secret, signing, hashlib.sha256).hexdigest()
        return {
            "X-AF-Timestamp": ts,
            "X-AF-Signature": sig,
            "X-AF-Key-Id":    key_id,
        }
