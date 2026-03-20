"""
pseudonymiser.py  —  Deterministic HMAC-SHA256 pseudonymisation
AI Fortress · Chapter 2 · Code Sample 2.B

Replaces PII values with deterministic tokens derived from HMAC-SHA256
using a secret key.  The same input + key always produces the same token,
preserving referential integrity across datasets (essential for training data
where subject IDs must remain consistent across multiple files).

Tokens are NOT reversible without the secret key.
The key must be stored separately (e.g. in AWS Secrets Manager / Vault).

GDPR Note: Pseudonymised data is still personal data under GDPR (Recital 26).
However, pseudonymisation reduces risk (Art.25, Art.32) and is recognised
as an appropriate safeguard for further processing under Art.89.
"""
from __future__ import annotations

import hashlib
import hmac
import base64
from typing import Optional
import pandas as pd


class Pseudonymiser:
    """
    HMAC-SHA256 deterministic pseudonymiser.

    Parameters
    ----------
    secret_key : bytes
        32-byte (256-bit) secret key. Store in Secrets Manager / Vault.
        Never hardcode. Generate with: os.urandom(32)
    prefix     : str
        Optional prefix for tokens to aid debugging (e.g. "PSE-")
    token_length : int
        Number of base64url characters in the output token (default: 16)
    """

    def __init__(
        self,
        secret_key:   bytes,
        prefix:       str = "",
        token_length: int = 16,
    ):
        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes; recommend 32")
        self.secret_key   = secret_key
        self.prefix       = prefix
        self.token_length = token_length

    def pseudonymise(self, value: str) -> str:
        """Return a deterministic pseudonym for the given value."""
        if not value or (isinstance(value, float)):
            return value  # type: ignore  # preserve NaN/None
        raw   = str(value).encode("utf-8")
        token = hmac.new(self.secret_key, raw, hashlib.sha256).digest()
        b64   = base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
        return self.prefix + b64[: self.token_length]

    def pseudonymise_column(
        self,
        df:     pd.DataFrame,
        column: str,
        inplace: bool = False,
    ) -> pd.DataFrame:
        """Apply pseudonymisation to an entire DataFrame column."""
        out = df if inplace else df.copy()
        out[column] = out[column].apply(
            lambda v: self.pseudonymise(str(v)) if pd.notna(v) else v
        )
        return out

    def pseudonymise_columns(
        self,
        df:      pd.DataFrame,
        columns: list[str],
    ) -> pd.DataFrame:
        """Pseudonymise multiple columns, returning a new DataFrame."""
        out = df.copy()
        for col in columns:
            if col in out.columns:
                out = self.pseudonymise_column(out, col, inplace=True)
        return out
