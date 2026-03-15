"""
cert_renewal_tracker.py  —  X.509 certificate renewal monitoring for ML services
AI Fortress · Chapter 9 · Code Sample 9.C

Monitors X.509 certificate expiry across the ML service mesh and triggers
renewal actions when thresholds are reached.

Renewal thresholds:
  CRITICAL (≤ 1 day)  — immediate renewal required
  WARNING  (≤ 7 days) — renewal this week
  INFO     (≤ 30 days)— schedule renewal

Renewal action stubs:
  acme_renew_fn   : Callable(hostname) → cert_pem  (e.g. certbot)
  spire_renew_fn  : Callable(spiffe_id) → cert_pem (SPIRE agent rotation)

Certificates can be loaded from PEM files, DER bytes, or registered
manually with an explicit expiry date (for certificates managed externally).
"""
from __future__ import annotations

import datetime
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend


_THRESHOLDS = [(1, "CRITICAL"), (7, "WARNING"), (30, "INFO")]


@dataclass
class CertEntry:
    cert_id:      str
    name:         str         # friendly name (e.g. "model-server mTLS cert")
    service:      str
    hostname:     str         # CN or primary SAN DNS
    spiffe_id:    str         # if this is a SVID
    expires_at:   str         # ISO8601
    issuer:       str
    serial:       str
    renewal_method: str       # "acme" | "spire" | "manual"
    last_renewed: str = ""


@dataclass
class RenewalAlert:
    cert_id:      str
    name:         str
    service:      str
    expires_at:   str
    days_remaining: int
    severity:     str
    message:      str
    renewal_method: str


@dataclass
class RenewalReport:
    total:     int
    critical:  int
    warning:   int
    info:      int
    ok:        int
    alerts:    List[RenewalAlert]
    renewed:   List[str]       # cert_ids successfully auto-renewed

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.critical == 0 else "❌"
        return (
            f"{icon} Cert renewal: {self.total} certs, "
            f"{self.critical} CRITICAL, {self.warning} WARNING, "
            f"{self.info} INFO, {self.ok} OK, {len(self.renewed)} auto-renewed."
        )


class CertRenewalTracker:
    """
    Monitors X.509 certificate expiry and triggers renewal.

    Parameters
    ----------
    acme_renew_fn  : Optional ACME renewal callable: (hostname) → new_cert_pem
    spire_renew_fn : Optional SPIRE rotation callable: (spiffe_id) → new_cert_pem
    auto_renew_days : Automatically trigger renewal if cert expires within this many days.
    audit_trail     : Optional RotationAuditTrail for logging renewals.
    """

    def __init__(
        self,
        acme_renew_fn:   Optional[Callable] = None,
        spire_renew_fn:  Optional[Callable] = None,
        auto_renew_days: int = 7,
        audit_trail=None,
    ):
        self._certs:     Dict[str, CertEntry] = {}
        self._acme       = acme_renew_fn
        self._spire      = spire_renew_fn
        self._auto_days  = auto_renew_days
        self._audit      = audit_trail

    def register_pem(
        self,
        cert_pem:        bytes,
        name:            str,
        service:         str,
        renewal_method:  str = "manual",
    ) -> CertEntry:
        """Parse and register a PEM certificate."""
        cert     = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return self._register_cert(cert, name, service, renewal_method)

    def register_manual(
        self,
        name:            str,
        service:         str,
        hostname:        str,
        expires_at:      str,      # ISO8601
        renewal_method:  str = "manual",
        spiffe_id:       str = "",
        issuer:          str = "",
        serial:          str = "",
    ) -> CertEntry:
        """Register a certificate by metadata only (no PEM required)."""
        cert_id = str(uuid.uuid4())
        entry   = CertEntry(
            cert_id        = cert_id,
            name           = name,
            service        = service,
            hostname       = hostname,
            spiffe_id      = spiffe_id,
            expires_at     = expires_at,
            issuer         = issuer,
            serial         = serial,
            renewal_method = renewal_method,
        )
        self._certs[cert_id] = entry
        return entry

    def check(
        self,
        now:      Optional[datetime.datetime] = None,
        auto_renew: bool = False,
    ) -> RenewalReport:
        """
        Check all registered certs. If `auto_renew=True`, trigger renewal
        for certs within `auto_renew_days` using the configured renew functions.
        """
        now = now or datetime.datetime.now(datetime.timezone.utc)
        alerts:  List[RenewalAlert] = []
        renewed: List[str]          = []
        counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "OK": 0}

        for entry in self._certs.values():
            try:
                exp = datetime.datetime.fromisoformat(entry.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue

            days_rem  = (exp - now).days
            severity  = None
            for threshold, sev in _THRESHOLDS:
                if days_rem <= threshold:
                    severity = sev
                    break

            if severity:
                counts[severity] += 1
                alerts.append(RenewalAlert(
                    cert_id        = entry.cert_id,
                    name           = entry.name,
                    service        = entry.service,
                    expires_at     = entry.expires_at,
                    days_remaining = max(0, days_rem),
                    severity       = severity,
                    message        = (
                        f"[{severity}] '{entry.name}' ({entry.service}) expires in "
                        f"{max(0, days_rem)} day(s). Renewal method: {entry.renewal_method}."
                    ),
                    renewal_method = entry.renewal_method,
                ))

                # Auto-renew if within threshold
                if auto_renew and days_rem <= self._auto_days:
                    if self._attempt_renewal(entry):
                        renewed.append(entry.cert_id)
                        if self._audit:
                            self._audit.log_rotation(
                                entry.service, "certificate",
                                detail=f"Auto-renewed cert '{entry.name}'"
                            )
            else:
                counts["OK"] += 1

        return RenewalReport(
            total    = len(self._certs),
            critical = counts["CRITICAL"],
            warning  = counts["WARNING"],
            info     = counts["INFO"],
            ok       = counts["OK"],
            alerts   = sorted(alerts, key=lambda a: a.days_remaining),
            renewed  = renewed,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _register_cert(
        self,
        cert:           x509.Certificate,
        name:           str,
        service:        str,
        renewal_method: str,
    ) -> CertEntry:
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
                    else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        # Extract hostname from CN
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        hostname = cn_attrs[0].value if cn_attrs else ""

        # Extract SPIFFE ID from SAN if present
        spiffe_id = ""
        try:
            san  = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
            spiffe_id = next((u for u in uris if u.startswith("spiffe://")), "")
        except Exception:
            pass

        cert_id = str(uuid.uuid4())
        entry   = CertEntry(
            cert_id        = cert_id,
            name           = name,
            service        = service,
            hostname       = hostname,
            spiffe_id      = spiffe_id,
            expires_at     = not_after.isoformat(),
            issuer         = cert.issuer.rfc4514_string(),
            serial         = str(cert.serial_number),
            renewal_method = renewal_method,
        )
        self._certs[cert_id] = entry
        return entry

    def _attempt_renewal(self, entry: CertEntry) -> bool:
        try:
            if entry.renewal_method == "acme" and self._acme:
                self._acme(entry.hostname)
                entry.last_renewed = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return True
            elif entry.renewal_method == "spire" and self._spire:
                self._spire(entry.spiffe_id)
                entry.last_renewed = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return True
        except Exception:
            pass
        return False
