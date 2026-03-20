"""
incident_classifier.py  —  AI security incident classifier
AI Fortress · Chapter 17 · Code Sample 17.A

Classifies AI security incidents by category, severity, and urgency.
Drives the initial triage decision: who to notify, which playbook to
activate, and whether immediate containment is required.

Severity model (adapted from CVSS + NIST CSF):
  P1 CRITICAL — active attack, exfiltration confirmed, high-risk AI decision
                stream affected; escalate to CISO immediately
  P2 HIGH     — confirmed breach, model integrity compromised, privacy impact
  P3 MEDIUM   — suspected breach, anomaly confirmed, fairness violation detected
  P4 LOW      — indicator of compromise, warning-level alert, near-miss

Category taxonomy: model_integrity | data_poisoning | privacy_breach |
  supply_chain | infrastructure | ota_edge | fairness | availability
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


_SEVERITY_SCORES: Dict[str, int] = {
    "confirmed_exfiltration":      10,
    "active_attack":               10,
    "model_weights_replaced":       9,
    "backdoor_confirmed":           9,
    "privacy_breach_confirmed":     9,
    "high_risk_ai_affected":        8,
    "supply_chain_compromise":      8,
    "training_data_poisoned":       7,
    "model_integrity_tampered":     7,
    "fairness_violation_confirmed": 6,
    "api_compromised":              6,
    "ota_compromise":               6,
    "membership_inference_confirmed": 6,
    "model_extraction_suspected":   5,
    "anomaly_detected":             4,
    "alert_threshold_breached":     3,
    "near_miss":                    2,
    "indicator_of_compromise":      2,
}

_CATEGORY_MAP: Dict[str, str] = {
    "confirmed_exfiltration":      "privacy_breach",
    "active_attack":               "infrastructure",
    "model_weights_replaced":      "model_integrity",
    "backdoor_confirmed":          "model_integrity",
    "privacy_breach_confirmed":    "privacy_breach",
    "high_risk_ai_affected":       "model_integrity",
    "supply_chain_compromise":     "supply_chain",
    "training_data_poisoned":      "data_poisoning",
    "model_integrity_tampered":    "model_integrity",
    "fairness_violation_confirmed":"fairness",
    "api_compromised":             "infrastructure",
    "ota_compromise":              "ota_edge",
    "membership_inference_confirmed": "privacy_breach",
    "model_extraction_suspected":  "privacy_breach",
    "anomaly_detected":            "availability",
    "alert_threshold_breached":    "availability",
    "near_miss":                   "infrastructure",
    "indicator_of_compromise":     "infrastructure",
}

_PLAYBOOK_MAP: Dict[str, str] = {
    "model_integrity":  "playbook-model-integrity-v1",
    "data_poisoning":   "playbook-data-poisoning-v1",
    "privacy_breach":   "playbook-privacy-breach-v1",
    "supply_chain":     "playbook-supply-chain-v1",
    "infrastructure":   "playbook-infrastructure-v1",
    "ota_edge":         "playbook-ota-edge-v1",
    "fairness":         "playbook-fairness-incident-v1",
    "availability":     "playbook-availability-v1",
}


@dataclass
class IncidentRecord:
    incident_id:      str
    title:            str
    indicators:       List[str]
    category:         str
    severity:         str        # "P1"|"P2"|"P3"|"P4"
    severity_score:   int
    playbook:         str
    immediate_actions: List[str]
    notify:           List[str]   # roles to notify
    created_at:       str
    status:           str = "open"


class IncidentClassifier:
    """
    Classifies AI security incidents from indicator lists.

    Parameters
    ----------
    custom_scores : Optional dict of custom indicator → score overrides.
    """

    def __init__(self, custom_scores: Optional[Dict[str, int]] = None):
        self._scores = {**_SEVERITY_SCORES, **(custom_scores or {})}

    def classify(
        self,
        title:      str,
        indicators: List[str],
        context:    Optional[Dict] = None,
    ) -> IncidentRecord:
        """
        Classify an incident from a list of observed indicators.

        Parameters
        ----------
        title      : Short description of the incident.
        indicators : List of indicator keys (see _SEVERITY_SCORES).
        context    : Optional dict with extra fields (e.g. system_name, env).
        """
        if not indicators:
            raise ValueError("At least one indicator is required")

        # Aggregate score (max of all indicators, not sum — avoids inflation)
        max_score = max(self._scores.get(ind, 1) for ind in indicators)

        # Determine category from highest-scoring indicator
        top_ind  = max(indicators, key=lambda i: self._scores.get(i, 1))
        category = _CATEGORY_MAP.get(top_ind, "infrastructure")

        severity = (
            "P1" if max_score >= 9 else
            "P2" if max_score >= 7 else
            "P3" if max_score >= 4 else
            "P4"
        )

        playbook = _PLAYBOOK_MAP.get(category, "playbook-general-v1")

        immediate, notify = self._response(severity, category)

        return IncidentRecord(
            incident_id      = str(uuid.uuid4())[:8],
            title            = title,
            indicators       = indicators,
            category         = category,
            severity         = severity,
            severity_score   = max_score,
            playbook         = playbook,
            immediate_actions = immediate,
            notify           = notify,
            created_at       = datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _response(severity: str, category: str):
        immediate: List[str] = []
        notify: List[str]    = ["ml-security-on-call"]

        if severity == "P1":
            immediate = [
                "Isolate affected system immediately",
                "Preserve all logs and model artefacts (immutable copy)",
                "Activate incident war room",
                "Do NOT restart or patch until forensics complete",
            ]
            notify = ["ciso", "ml-security-on-call", "dpo", "legal", "cto"]
        elif severity == "P2":
            immediate = [
                "Suspend automated decisions from affected model",
                "Preserve logs and model artefacts",
                "Begin forensic evidence collection",
            ]
            notify = ["ciso", "ml-security-on-call", "dpo"]
        elif severity == "P3":
            immediate = [
                "Increase monitoring on affected system",
                "Snapshot current model and data state",
                "Begin investigation",
            ]
            notify = ["ml-security-on-call", "ml-ops-lead"]
        else:
            immediate = ["Log and monitor", "Assign to next sprint if not escalated"]
            notify    = ["ml-security-on-call"]

        if category == "privacy_breach" and severity in ("P1", "P2"):
            notify.append("data-subjects-notification-required")
        if category == "fairness" and severity in ("P1", "P2", "P3"):
            notify.append("ai-ethics-lead")

        return immediate, list(dict.fromkeys(notify))   # deduplicated
