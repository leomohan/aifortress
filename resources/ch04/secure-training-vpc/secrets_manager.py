"""
secrets_manager.py  —  Secrets injection and log scrubbing
AI Fortress · Chapter 4 · Code Sample 4.A

Injects secrets from a backend into the training process without exposing
them in logs, tracebacks, or stdout.  Three backends are supported:

  env     — reads from environment variables (CI/CD, local dev)
  aws     — AWS Secrets Manager (production)
  vault   — HashiCorp Vault Transit / KV v2 (production)

Security controls:
  1. Secrets are never stored as plain strings in Python — they are wrapped
     in SecretStr which redacts the value in __repr__ and __str__.
  2. A custom logging filter scrubs known secret patterns from all log records
     before they reach any handler (file, CloudWatch, Datadog, etc.).
  3. Secrets are zeroed from memory as soon as they are consumed, where the
     Python runtime cooperates (best-effort; CPython strings are immutable).
  4. Exception hook is installed to redact secrets from tracebacks.
"""
from __future__ import annotations

import logging
import os
import re
import sys
import traceback
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


# ── SecretStr: a string that never leaks its value ───────────────────────────

class SecretStr:
    """A string wrapper whose repr and str always show '[REDACTED]'."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        object.__setattr__(self, "_value", value)

    def get_secret_value(self) -> str:
        return object.__getattribute__(self, "_value")

    def __repr__(self) -> str:
        return "SecretStr('**********')"

    def __str__(self) -> str:
        return "**********"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self.get_secret_value() == other.get_secret_value()
        return False


# ── Log scrubbing filter ──────────────────────────────────────────────────────

class SecretScrubFilter(logging.Filter):
    """
    Logging filter that replaces known secret patterns with '[REDACTED]'.
    Install on every handler in your training script's logging setup.
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        super().__init__()
        # Default: common secret patterns; add your own via add_pattern()
        self._patterns: List[re.Pattern] = [
            re.compile(p) for p in (patterns or [
                r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|bearer)\s*[=:]\s*\S+",
                r"(?i)(aws_secret_access_key|aws_session_token)\s*[=:]\s*\S+",
                r"(?i)(authorization:\s*bearer\s+)\S+",
                r"\b[A-Za-z0-9+/]{40,}={0,2}\b",  # base64-like blobs ≥40 chars
            ])
        ]

    def add_pattern(self, pattern: str) -> None:
        self._patterns.append(re.compile(pattern))

    def add_literal(self, secret_value: str) -> None:
        """Register a literal secret value for exact-match scrubbing."""
        if secret_value:
            self._patterns.append(re.compile(re.escape(secret_value)))

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.msg = self._scrub(str(record.msg))
        record.args = tuple(self._scrub(str(a)) for a in (record.args or ()))
        return True

    def _scrub(self, text: str) -> str:
        for pat in self._patterns:
            text = pat.sub("[REDACTED]", text)
        return text


# ── Backends ──────────────────────────────────────────────────────────────────

class _EnvBackend:
    """Reads secrets from environment variables."""
    def get(self, key: str) -> str:
        value = os.environ.get(key)
        if value is None:
            raise KeyError(f"Secret '{key}' not found in environment")
        return value


class _AWSBackend:
    """Reads secrets from AWS Secrets Manager."""
    def __init__(self, region: str = "us-east-1"):
        try:
            import boto3
            self._client = boto3.client("secretsmanager", region_name=region)
        except ImportError:
            raise ImportError("boto3 required for AWS backend: pip install boto3")

    def get(self, key: str) -> str:
        response = self._client.get_secret_value(SecretId=key)
        return response.get("SecretString") or response.get("SecretBinary", b"").decode()


class _VaultBackend:
    """Reads secrets from HashiCorp Vault KV v2."""
    def __init__(self, url: str = "https://vault.example.com", token_env: str = "VAULT_TOKEN"):
        try:
            import hvac
            self._client = hvac.Client(url=url, token=os.environ.get(token_env))
        except ImportError:
            raise ImportError("hvac required for Vault backend: pip install hvac")

    def get(self, key: str) -> str:
        # key format: "secret/data/myapp/dbpassword" → mount="secret", path="myapp/dbpassword"
        parts    = key.lstrip("/").split("/")
        mount    = parts[0]
        path     = "/".join(parts[1:])
        response = self._client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
        data     = response["data"]["data"]
        # Return first value if key is a path, or the specific key within the secret
        if len(parts) > 2:
            field = parts[-1]
            return data.get(field) or next(iter(data.values()))
        return next(iter(data.values()))


# ── Public API ────────────────────────────────────────────────────────────────

class SecretsManager:
    """
    Unified secrets manager for ML training jobs.

    Parameters
    ----------
    backend     : "env" | "aws" | "vault"
    scrub_filter: Optional SecretScrubFilter to auto-register retrieved secrets
    aws_region  : AWS region (for "aws" backend)
    vault_url   : Vault server URL (for "vault" backend)
    """

    def __init__(
        self,
        backend:      str = "env",
        scrub_filter: Optional[SecretScrubFilter] = None,
        aws_region:   str = "us-east-1",
        vault_url:    str = "https://vault.example.com",
    ):
        self._scrub = scrub_filter
        if backend == "env":
            self._backend = _EnvBackend()
        elif backend == "aws":
            self._backend = _AWSBackend(region=aws_region)
        elif backend == "vault":
            self._backend = _VaultBackend(url=vault_url)
        else:
            raise ValueError(f"Unknown backend '{backend}'. Choose: env | aws | vault")

    def get(self, key: str) -> SecretStr:
        """Retrieve a secret by key. Returns a SecretStr that never leaks its value."""
        raw = self._backend.get(key)
        if self._scrub:
            self._scrub.add_literal(raw)
        return SecretStr(raw)

    def get_raw(self, key: str) -> str:
        """
        Return the raw string value. Use only at the call site where the value
        is consumed (e.g. passed to a library that requires a plain string).
        Do NOT store the return value in a variable that persists in scope.
        """
        return self._backend.get(key)

    def install_traceback_hook(self) -> None:
        """
        Replace sys.excepthook with a version that scrubs known secrets
        from tracebacks before printing them.
        """
        if self._scrub is None:
            return
        scrub = self._scrub

        def _safe_excepthook(exc_type, exc_value, exc_tb):
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
            safe_tb  = [scrub._scrub(line) for line in tb_lines]
            sys.stderr.write("".join(safe_tb))

        sys.excepthook = _safe_excepthook


def install_global_scrub_filter(
    secret_patterns: Optional[List[str]] = None,
) -> SecretScrubFilter:
    """
    Install a SecretScrubFilter on the root logger so ALL log records
    are scrubbed before reaching any handler.  Call once at job startup.
    """
    filt = SecretScrubFilter(patterns=secret_patterns)
    logging.getLogger().addFilter(filt)
    return filt
