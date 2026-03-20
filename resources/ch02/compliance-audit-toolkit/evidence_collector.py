"""
evidence_collector.py  —  Gather audit evidence from the governance database
AI Fortress · Chapter 2 · Code Sample 2.C
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class AuditEvidence:
    """A flat dictionary of evidence flags collected for a given dataset."""
    dataset_id: str
    evidence:   Dict[str, Any] = field(default_factory=dict)

    def has(self, key: str) -> bool:
        v = self.evidence.get(key)
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v > 0
        return bool(v)


class EvidenceCollector:
    """
    Collects evidence from the governance database and returns an AuditEvidence
    object.  In production, connect this to your actual governance store.
    For testing, pass evidence_overrides directly.
    """

    def __init__(
        self,
        governance_db: str = "",
        evidence_overrides: Dict[str, Any] | None = None,
    ):
        self.governance_db      = governance_db
        self.evidence_overrides = evidence_overrides or {}

    def collect(self, dataset_id: str) -> AuditEvidence:
        """
        Collect all available evidence for a dataset.
        Extend each _check_* method to query your real governance store.
        """
        ev: Dict[str, Any] = {}
        ev["lawful_basis_registered"]         = self._check_lawful_basis(dataset_id)
        ev["purpose_documented"]              = self._check_purpose(dataset_id)
        ev["data_categories_documented"]      = self._check_data_categories(dataset_id)
        ev["retention_policy_declared"]       = self._check_retention_policy(dataset_id)
        ev["deletion_certificates_present"]   = self._check_deletion_certs(dataset_id)
        ev["encryption_at_rest"]              = self._check_encryption(dataset_id)
        ev["encryption_in_transit"]           = self._check_tls(dataset_id)
        ev["access_controls_documented"]      = self._check_access_controls(dataset_id)
        ev["dsr_workflow_operational"]        = self._check_dsr_workflow()
        ev["erasure_sla_met"]                 = self._check_erasure_sla()
        ev["ropa_current"]                    = self._check_ropa()
        ev["dpia_completed"]                  = self._check_dpia(dataset_id)
        ev["pseudonymisation_applied"]        = self._check_pseudonymisation(dataset_id)
        ev["transfer_controls_documented"]    = self._check_transfer_controls()
        ev["audit_logs_present"]              = self._check_audit_logs()
        ev["integrity_verification_present"]  = self._check_integrity()
        ev["privacy_notice_present"]          = self._check_privacy_notice()
        ev["opt_out_mechanism_documented"]    = self._check_opt_out()
        ev["baa_documented"]                  = self._check_baa()
        ev["minimisation_review"]             = self._check_minimisation(dataset_id)
        ev["transparency_documentation_present"] = self._check_transparency()
        ev["risk_register_present"]           = self._check_risk_register()

        # Apply any test overrides
        ev.update(self.evidence_overrides)
        return AuditEvidence(dataset_id=dataset_id, evidence=ev)

    # ── Stub checks — replace with real DB queries ────────────────────────────
    def _check_lawful_basis(self, dataset_id): return False
    def _check_purpose(self, dataset_id):      return False
    def _check_data_categories(self, dataset_id): return False
    def _check_retention_policy(self, dataset_id): return False
    def _check_deletion_certs(self, dataset_id):   return False
    def _check_encryption(self, dataset_id):       return False
    def _check_tls(self, dataset_id):              return False
    def _check_access_controls(self, dataset_id):  return False
    def _check_dsr_workflow(self):                 return False
    def _check_erasure_sla(self):                  return False
    def _check_ropa(self):                         return False
    def _check_dpia(self, dataset_id):             return False
    def _check_pseudonymisation(self, dataset_id): return False
    def _check_transfer_controls(self):            return False
    def _check_audit_logs(self):                   return False
    def _check_integrity(self):                    return False
    def _check_privacy_notice(self):               return False
    def _check_opt_out(self):                      return False
    def _check_baa(self):                          return False
    def _check_minimisation(self, dataset_id):     return False
    def _check_transparency(self):                 return False
    def _check_risk_register(self):                return False
