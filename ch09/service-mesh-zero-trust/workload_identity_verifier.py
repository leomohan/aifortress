"""
workload_identity_verifier.py  —  SPIFFE/X.509 SVID workload identity verification
AI Fortress · Chapter 9 · Code Sample 9.B

Validates SPIFFE SVIDs (X.509 certificates with SPIFFE URIs in the SAN)
for service-to-service authentication in an ML microservice mesh.

SPIFFE standard: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/

Controls applied:
  - X.509 certificate chain validation against a trusted CA bundle
  - SPIFFE URI extraction from Subject Alternative Names (URI SANs)
  - Trust domain enforcement (only URIs in allowed trust domains accepted)
  - Certificate expiry check with configurable warning threshold
  - Workload allowlist: optional set of SPIFFE IDs permitted to connect

SPIFFE URI format: spiffe://<trust-domain>/<workload-path>
Example:           spiffe://ml-platform.example.com/ns/inference/sa/model-server
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Set

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend


SPIFFE_SCHEME = "spiffe://"
EXPIRY_WARN_DAYS = 30


@dataclass
class WorkloadIdentity:
    spiffe_id:    str           # full spiffe://trust-domain/workload URI
    trust_domain: str           # extracted trust domain
    workload:     str           # path component after trust domain
    common_name:  str
    expires_at:   datetime.datetime
    issuer:       str
    expiry_warning: bool = False


@dataclass
class IdentityVerifyResult:
    verified:   bool
    identity:   Optional[WorkloadIdentity]
    reason:     str


class WorkloadIdentityError(ValueError):
    pass


class WorkloadIdentityVerifier:
    """
    Validates SPIFFE SVIDs for ML workload-to-workload authentication.

    Parameters
    ----------
    trusted_ca_pems   : List of PEM-encoded CA certificates to trust.
    allowed_trust_domains : If set, only SPIFFE IDs from these trust
                            domains are accepted.
    allowed_spiffe_ids    : If set, only these exact SPIFFE IDs are accepted
                            (in addition to trust domain check).
    expiry_warn_days      : Warn if certificate expires within this many days.
    """

    def __init__(
        self,
        trusted_ca_pems:       List[bytes],
        allowed_trust_domains: Optional[Set[str]] = None,
        allowed_spiffe_ids:    Optional[Set[str]] = None,
        expiry_warn_days:      int = EXPIRY_WARN_DAYS,
    ):
        self._ca_certs   = [x509.load_pem_x509_certificate(pem, default_backend())
                            for pem in trusted_ca_pems]
        self._trust_domains = allowed_trust_domains
        self._allowed_ids   = allowed_spiffe_ids
        self._warn_days     = expiry_warn_days

    def verify_pem(self, cert_pem: bytes) -> IdentityVerifyResult:
        """Verify a PEM-encoded X.509 SVID."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            return self._verify_cert(cert)
        except WorkloadIdentityError as e:
            return IdentityVerifyResult(verified=False, identity=None, reason=str(e))
        except Exception as e:
            return IdentityVerifyResult(verified=False, identity=None,
                                        reason=f"Certificate parse error: {e}")

    def verify_der(self, cert_der: bytes) -> IdentityVerifyResult:
        """Verify a DER-encoded X.509 SVID."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            return self._verify_cert(cert)
        except WorkloadIdentityError as e:
            return IdentityVerifyResult(verified=False, identity=None, reason=str(e))
        except Exception as e:
            return IdentityVerifyResult(verified=False, identity=None,
                                        reason=f"Certificate parse error: {e}")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _verify_cert(self, cert: x509.Certificate) -> IdentityVerifyResult:
        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Expiry
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
                    else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") \
                     else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

        if now > not_after:
            raise WorkloadIdentityError(f"Certificate expired at {not_after.isoformat()}")
        if now < not_before:
            raise WorkloadIdentityError(f"Certificate not yet valid (nbf={not_before.isoformat()})")

        # 2. Extract SPIFFE URI from SAN
        spiffe_id = self._extract_spiffe_id(cert)
        if not spiffe_id:
            raise WorkloadIdentityError(
                "No SPIFFE URI found in certificate Subject Alternative Names"
            )

        # 3. Trust domain check
        trust_domain = self._parse_trust_domain(spiffe_id)
        if self._trust_domains and trust_domain not in self._trust_domains:
            raise WorkloadIdentityError(
                f"Trust domain '{trust_domain}' not in allowed set: {self._trust_domains}"
            )

        # 4. Allowed SPIFFE ID check
        if self._allowed_ids and spiffe_id not in self._allowed_ids:
            raise WorkloadIdentityError(
                f"SPIFFE ID '{spiffe_id}' not in allowed workload set"
            )

        # 5. CA chain validation (signature check against trusted CA certs)
        self._verify_chain(cert)

        expiry_warn = (not_after - now).days < self._warn_days

        workload = spiffe_id[len(SPIFFE_SCHEME) + len(trust_domain):]
        identity = WorkloadIdentity(
            spiffe_id      = spiffe_id,
            trust_domain   = trust_domain,
            workload       = workload.lstrip("/"),
            common_name    = cert.subject.get_attributes_for_oid(
                                 x509.NameOID.COMMON_NAME)[0].value
                             if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                             else "",
            expires_at     = not_after,
            issuer         = cert.issuer.rfc4514_string(),
            expiry_warning = expiry_warn,
        )
        return IdentityVerifyResult(verified=True, identity=identity, reason="OK")

    @staticmethod
    def _extract_spiffe_id(cert: x509.Certificate) -> Optional[str]:
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for uri in san_ext.value.get_values_for_type(x509.UniformResourceIdentifier):
                if uri.startswith(SPIFFE_SCHEME):
                    return uri
        except x509.ExtensionNotFound:
            pass
        return None

    @staticmethod
    def _parse_trust_domain(spiffe_id: str) -> str:
        """Extract trust domain from spiffe://trust-domain/workload"""
        without_scheme = spiffe_id[len(SPIFFE_SCHEME):]
        return without_scheme.split("/")[0]

    def _verify_chain(self, cert: x509.Certificate) -> None:
        """
        Verify that `cert` is signed by one of the trusted CA certs.
        For a full implementation, use OpenSSL or cryptography's full chain
        validation. This implementation checks direct signing by a trusted CA.
        """
        if not self._ca_certs:
            return  # No CAs configured — skip chain validation

        for ca_cert in self._ca_certs:
            try:
                ca_pub = ca_cert.public_key()
                ca_pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm,
                )
                return  # Valid chain found
            except Exception:
                continue

        raise WorkloadIdentityError(
            "Certificate is not signed by any trusted CA"
        )

    @staticmethod
    def generate_test_svid(
        trust_domain: str,
        workload:     str,
        ca_key=None,
        ca_cert=None,
        ttl_days:     int = 1,
    ):
        """
        Generate a self-signed test SVID for unit tests.
        Returns (cert_pem, key_pem, ca_cert_pem).
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509 import random_serial_number

        # Generate CA key if not provided
        if ca_key is None:
            ca_key  = ec.generate_private_key(ec.SECP256R1())
            ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")])
            now     = datetime.datetime.now(datetime.timezone.utc)
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)
                .public_key(ca_key.public_key())
                .serial_number(random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(ca_key, hashes.SHA256())
            )

        # Generate workload key and SVID
        workload_key  = ec.generate_private_key(ec.SECP256R1())
        spiffe_uri    = f"spiffe://{trust_domain}/{workload}"
        now           = datetime.datetime.now(datetime.timezone.utc)
        svid_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, workload)
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(workload_key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=ttl_days))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(spiffe_uri)
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem    = svid_cert.public_bytes(serialization.Encoding.PEM)
        key_pem     = workload_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        return cert_pem, key_pem, ca_cert_pem, ca_key, ca_cert
