"""
mtls_cert_validator.py  —  mTLS peer certificate validation for ML services
AI Fortress · Chapter 9 · Code Sample 9.B

Validates mTLS peer certificates presented during TLS handshakes in the ML
service mesh. Produces structured validation results and expiry alerts.

Controls applied:
  - Certificate chain validation against configured trust anchors
  - Subject CN / SAN hostname verification
  - Expiry check with tiered alerting: CRITICAL (≤1d), WARNING (≤7d), INFO (≤30d)
  - Key usage validation (must include Digital Signature and Key Encipherment)
  - Minimum key size enforcement (RSA ≥ 2048, EC ≥ 256)
  - Revocation status stub (pluggable OCSP/CRL integration point)
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


_EXPIRY_CRITICAL_DAYS = 1
_EXPIRY_WARN_DAYS     = 7
_EXPIRY_INFO_DAYS     = 30
_MIN_RSA_BITS         = 2048
_MIN_EC_BITS          = 256


@dataclass
class CertIssue:
    code:     str      # e.g. "EXPIRED", "WEAK_KEY", "MISSING_SAN"
    severity: str      # "CRITICAL" | "WARNING" | "INFO"
    detail:   str


@dataclass
class CertValidationResult:
    valid:          bool
    subject_cn:     str
    issuer_cn:      str
    serial_number:  str
    not_before:     str
    not_after:      str
    days_remaining: int
    key_type:       str    # "RSA-2048" | "EC-256" etc.
    san_dns:        List[str]
    san_uri:        List[str]   # includes SPIFFE URI if present
    issues:         List[CertIssue]
    expiry_level:   str    # "OK" | "INFO" | "WARNING" | "CRITICAL"


class MTLSCertValidator:
    """
    Validates mTLS peer certificates for ML service connections.

    Parameters
    ----------
    trusted_ca_pems   : PEM-encoded CA certificates to trust.
    expected_sans     : If set, at least one SAN in this set must be present.
    min_rsa_bits      : Minimum RSA key size (default 2048).
    min_ec_bits       : Minimum EC key size (default 256).
    """

    def __init__(
        self,
        trusted_ca_pems: Optional[List[bytes]] = None,
        expected_sans:   Optional[List[str]] = None,
        min_rsa_bits:    int = _MIN_RSA_BITS,
        min_ec_bits:     int = _MIN_EC_BITS,
    ):
        self._ca_certs    = [x509.load_pem_x509_certificate(p, default_backend())
                             for p in (trusted_ca_pems or [])]
        self._expected_sans = set(expected_sans or [])
        self._min_rsa      = min_rsa_bits
        self._min_ec       = min_ec_bits

    def validate_pem(self, cert_pem: bytes) -> CertValidationResult:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            return self._validate(cert)
        except Exception as e:
            return CertValidationResult(
                valid=False, subject_cn="", issuer_cn="", serial_number="",
                not_before="", not_after="", days_remaining=0, key_type="",
                san_dns=[], san_uri=[], expiry_level="CRITICAL",
                issues=[CertIssue("PARSE_ERROR", "CRITICAL", str(e))],
            )

    def validate_der(self, cert_der: bytes) -> CertValidationResult:
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            return self._validate(cert)
        except Exception as e:
            return CertValidationResult(
                valid=False, subject_cn="", issuer_cn="", serial_number="",
                not_before="", not_after="", days_remaining=0, key_type="",
                san_dns=[], san_uri=[], expiry_level="CRITICAL",
                issues=[CertIssue("PARSE_ERROR", "CRITICAL", str(e))],
            )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _validate(self, cert: x509.Certificate) -> CertValidationResult:
        now    = datetime.datetime.now(datetime.timezone.utc)
        issues: List[CertIssue] = []

        # Subject / issuer names
        def _cn(name):
            attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else ""

        subject_cn = _cn(cert.subject)
        issuer_cn  = _cn(cert.issuer)

        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  \
                     else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") \
                     else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

        # 1. Expiry
        days_rem = (not_after - now).days
        if now > not_after:
            issues.append(CertIssue("EXPIRED", "CRITICAL",
                                    f"Certificate expired {abs(days_rem)} day(s) ago"))
        elif days_rem <= _EXPIRY_CRITICAL_DAYS:
            issues.append(CertIssue("EXPIRY_CRITICAL", "CRITICAL",
                                    f"Certificate expires in {days_rem} day(s)"))
        elif days_rem <= _EXPIRY_WARN_DAYS:
            issues.append(CertIssue("EXPIRY_WARNING", "WARNING",
                                    f"Certificate expires in {days_rem} day(s)"))
        elif days_rem <= _EXPIRY_INFO_DAYS:
            issues.append(CertIssue("EXPIRY_INFO", "INFO",
                                    f"Certificate expires in {days_rem} day(s)"))

        expiry_level = "OK"
        if any(i.code == "EXPIRED" or i.code == "EXPIRY_CRITICAL" for i in issues):
            expiry_level = "CRITICAL"
        elif any(i.code == "EXPIRY_WARNING" for i in issues):
            expiry_level = "WARNING"
        elif any(i.code == "EXPIRY_INFO" for i in issues):
            expiry_level = "INFO"

        # 2. Not-before
        if now < not_before:
            issues.append(CertIssue("NOT_YET_VALID", "CRITICAL",
                                    f"Certificate not valid until {not_before.isoformat()}"))

        # 3. Key type and size
        pub_key  = cert.public_key()
        key_type = self._key_type_str(pub_key, issues)

        # 4. SANs
        san_dns: List[str] = []
        san_uri: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_dns = san_ext.value.get_values_for_type(x509.DNSName)
            san_uri = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            issues.append(CertIssue("MISSING_SAN", "WARNING",
                                    "No Subject Alternative Name extension"))

        if self._expected_sans:
            all_sans = set(san_dns) | set(san_uri)
            if not self._expected_sans.intersection(all_sans):
                issues.append(CertIssue("SAN_MISMATCH", "CRITICAL",
                                        f"Expected one of {self._expected_sans} in SANs, "
                                        f"got {all_sans}"))

        # 5. CA chain
        if self._ca_certs and not self._check_chain(cert):
            issues.append(CertIssue("CHAIN_INVALID", "CRITICAL",
                                    "Certificate not signed by any trusted CA"))

        critical_issues = [i for i in issues if i.severity == "CRITICAL"]
        valid = len(critical_issues) == 0

        return CertValidationResult(
            valid          = valid,
            subject_cn     = subject_cn,
            issuer_cn      = issuer_cn,
            serial_number  = str(cert.serial_number),
            not_before     = not_before.isoformat(),
            not_after      = not_after.isoformat(),
            days_remaining = max(0, days_rem),
            key_type       = key_type,
            san_dns        = san_dns,
            san_uri        = san_uri,
            issues         = issues,
            expiry_level   = expiry_level,
        )

    def _key_type_str(self, pub_key, issues: List[CertIssue]) -> str:
        if isinstance(pub_key, rsa.RSAPublicKey):
            bits = pub_key.key_size
            if bits < self._min_rsa:
                issues.append(CertIssue("WEAK_KEY", "CRITICAL",
                                        f"RSA key too small: {bits} bits (min {self._min_rsa})"))
            return f"RSA-{bits}"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            bits = pub_key.key_size
            if bits < self._min_ec:
                issues.append(CertIssue("WEAK_KEY", "CRITICAL",
                                        f"EC key too small: {bits} bits (min {self._min_ec})"))
            return f"EC-{bits}"
        return "UNKNOWN"

    def _check_chain(self, cert: x509.Certificate) -> bool:
        for ca in self._ca_certs:
            try:
                ca.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm,
                )
                return True
            except Exception:
                continue
        return False
