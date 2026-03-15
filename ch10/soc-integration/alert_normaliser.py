"""
alert_normaliser.py  —  ML security alert normalisation to SIEM formats
AI Fortress · Chapter 10 · Code Sample 10.B

Converts raw ML security events into industry-standard SIEM formats:
  - CEF  (ArcSight Common Event Format)      — Splunk, ArcSight
  - LEEF (Log Event Extended Format)          — IBM QRadar
  - JSON (structured)                         — Microsoft Sentinel, Elastic

ML event types mapped:
  drift_critical     → CEF severity 9 / LEEF SEV=High
  drift_warning      → CEF severity 6 / LEEF SEV=Medium
  auth_failure       → CEF severity 8
  ip_deny            → CEF severity 7
  signing_failure    → CEF severity 8
  lateral_movement   → CEF severity 10 (CRITICAL)
  rotation_failure   → CEF severity 7
  model_extraction   → CEF severity 10 (CRITICAL)
  supply_chain       → CEF severity 10 (CRITICAL)

CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
             SignatureID|Name|Severity|Extension
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Event type catalogue ──────────────────────────────────────────────────────

_EVENT_CATALOGUE = {
    "drift_critical":   {"sig": "AIF-001", "name": "ML Feature Drift Critical",    "cef_sev": 9,  "leef_sev": "High"},
    "drift_warning":    {"sig": "AIF-002", "name": "ML Feature Drift Warning",     "cef_sev": 6,  "leef_sev": "Medium"},
    "prediction_drift": {"sig": "AIF-003", "name": "ML Prediction Drift",          "cef_sev": 7,  "leef_sev": "High"},
    "auth_failure":     {"sig": "AIF-010", "name": "ML API Auth Failure",          "cef_sev": 8,  "leef_sev": "High"},
    "ip_deny":          {"sig": "AIF-011", "name": "ML API IP Policy Deny",        "cef_sev": 7,  "leef_sev": "Medium"},
    "signing_failure":  {"sig": "AIF-012", "name": "ML API Request Signing Fail",  "cef_sev": 8,  "leef_sev": "High"},
    "rate_limit":       {"sig": "AIF-013", "name": "ML API Rate Limit Exceeded",   "cef_sev": 5,  "leef_sev": "Low"},
    "lateral_movement": {"sig": "AIF-020", "name": "ML Mesh Lateral Movement",     "cef_sev": 10, "leef_sev": "Critical"},
    "rotation_failure": {"sig": "AIF-030", "name": "Secret Rotation Failure",      "cef_sev": 7,  "leef_sev": "High"},
    "cert_expiry":      {"sig": "AIF-031", "name": "Certificate Expiry Alert",     "cef_sev": 6,  "leef_sev": "Medium"},
    "model_extraction": {"sig": "AIF-040", "name": "ML Model Extraction Attempt",  "cef_sev": 10, "leef_sev": "Critical"},
    "supply_chain":     {"sig": "AIF-041", "name": "ML Supply Chain Compromise",   "cef_sev": 10, "leef_sev": "Critical"},
    "importance_drift": {"sig": "AIF-050", "name": "Feature Importance Drift",     "cef_sev": 7,  "leef_sev": "High"},
}

_DEVICE_VENDOR  = "AI Fortress"
_DEVICE_PRODUCT = "ML Security Monitor"
_DEVICE_VERSION = "1.0"
_CEF_VERSION    = "0"


@dataclass
class RawMLEvent:
    event_type:  str
    source_ip:   str = ""
    dest_ip:     str = ""
    user:        str = ""
    model_name:  str = ""
    detail:      str = ""
    metadata:    Dict[str, Any] = field(default_factory=dict)
    timestamp:   str = ""
    event_id:    str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.event_id:
            self.event_id = str(uuid.uuid4())


@dataclass
class NormalisedAlert:
    event_id:    str
    event_type:  str
    timestamp:   str
    severity:    int          # 0–10 (CEF scale)
    cef:         str
    leef:        str
    json_record: dict


def _cef_escape(s: str) -> str:
    """Escape special characters in CEF extension values."""
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def _leef_escape(s: str) -> str:
    """Escape tab and newline in LEEF values."""
    return str(s).replace("\t", " ").replace("\n", " ")


class AlertNormaliser:
    """
    Normalises raw ML security events to CEF, LEEF, and JSON formats.

    Parameters
    ----------
    device_vendor  : Override device vendor string in CEF/LEEF headers.
    device_product : Override device product string.
    """

    def __init__(
        self,
        device_vendor:  str = _DEVICE_VENDOR,
        device_product: str = _DEVICE_PRODUCT,
    ):
        self.vendor  = device_vendor
        self.product = device_product

    def normalise(self, event: RawMLEvent) -> NormalisedAlert:
        """Normalise a single RawMLEvent to all three formats."""
        meta = _EVENT_CATALOGUE.get(event.event_type, {
            "sig": "AIF-999", "name": event.event_type,
            "cef_sev": 5, "leef_sev": "Medium",
        })

        cef_str  = self._to_cef(event, meta)
        leef_str = self._to_leef(event, meta)
        json_rec = self._to_json(event, meta)

        return NormalisedAlert(
            event_id    = event.event_id,
            event_type  = event.event_type,
            timestamp   = event.timestamp,
            severity    = meta["cef_sev"],
            cef         = cef_str,
            leef        = leef_str,
            json_record = json_rec,
        )

    def normalise_batch(self, events: List[RawMLEvent]) -> List[NormalisedAlert]:
        return [self.normalise(e) for e in events]

    # ── Format builders ───────────────────────────────────────────────────────

    def _to_cef(self, event: RawMLEvent, meta: dict) -> str:
        ext_parts = []

        def add(key: str, val: Any):
            if val:
                ext_parts.append(f"{key}={_cef_escape(val)}")

        add("rt",      event.timestamp)
        add("src",     event.source_ip)
        add("dst",     event.dest_ip)
        add("suser",   event.user)
        add("cs1",     event.model_name)
        add("cs1Label","modelName")
        add("msg",     event.detail)
        add("externalId", event.event_id)

        for k, v in (event.metadata or {}).items():
            safe_k = re.sub(r"[^a-zA-Z0-9]", "_", str(k))[:50]
            add(f"cs2",    f"{safe_k}={v}")

        ext = " ".join(ext_parts)
        header = (
            f"CEF:{_CEF_VERSION}"
            f"|{self.vendor}"
            f"|{self.product}"
            f"|{_DEVICE_VERSION}"
            f"|{meta['sig']}"
            f"|{meta['name']}"
            f"|{meta['cef_sev']}"
            f"|{ext}"
        )
        return header

    def _to_leef(self, event: RawMLEvent, meta: dict) -> str:
        attrs = {
            "devTime":    event.timestamp,
            "src":        event.source_ip,
            "dst":        event.dest_ip,
            "usrName":    event.user,
            "modelName":  event.model_name,
            "msg":        event.detail,
            "sev":        meta["leef_sev"],
            "eventId":    event.event_id,
        }
        for k, v in (event.metadata or {}).items():
            safe_k = re.sub(r"[^a-zA-Z0-9_]", "_", str(k))[:50]
            attrs[safe_k] = str(v)

        pairs  = "\t".join(f"{k}={_leef_escape(v)}" for k, v in attrs.items() if v)
        header = f"LEEF:2.0|{self.vendor}|{self.product}|{_DEVICE_VERSION}|{meta['sig']}|"
        return header + pairs

    def _to_json(self, event: RawMLEvent, meta: dict) -> dict:
        return {
            "event_id":    event.event_id,
            "timestamp":   event.timestamp,
            "event_type":  event.event_type,
            "signature":   meta["sig"],
            "name":        meta["name"],
            "severity":    meta["cef_sev"],
            "severity_label": meta["leef_sev"],
            "source_ip":   event.source_ip,
            "dest_ip":     event.dest_ip,
            "user":        event.user,
            "model_name":  event.model_name,
            "detail":      event.detail,
            "metadata":    event.metadata,
            "device":      {"vendor": self.vendor, "product": self.product,
                            "version": _DEVICE_VERSION},
        }
