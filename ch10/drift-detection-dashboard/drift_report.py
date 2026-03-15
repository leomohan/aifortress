"""
drift_report.py  —  Aggregated drift report for ML model monitoring
AI Fortress · Chapter 10 · Code Sample 10.A

Aggregates feature drift, prediction drift, and importance drift signals
into a single structured report with an overall drift score (0–100) and
a configurable pass/fail gate.

Overall drift score:
  score = max(feature_score, prediction_score, importance_score)
  where each sub-score is: CRITICAL=100, WARNING=50, OK=0

The report is saved as JSON for downstream ingestion by SIEM/SOC systems.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from feature_drift_detector import FeatureDriftReport
from prediction_drift_monitor import PredictionDriftResult
from feature_importance_drift import ImportanceDriftResult


_STATUS_SCORE = {"CRITICAL": 100, "WARNING": 50, "OK": 0}


@dataclass
class DriftReport:
    report_id:       str
    timestamp:       str
    model_name:      str
    model_version:   str
    window_start:    str
    window_end:      str
    overall_score:   int         # 0–100
    overall_status:  str         # "OK" | "WARNING" | "CRITICAL"
    feature_drift:   dict        # FeatureDriftReport.asdict()
    prediction_drift: dict       # PredictionDriftResult.asdict()
    importance_drift: dict       # ImportanceDriftResult.asdict()
    recommendations: List[str]
    overall_pass:    bool        # True if score < fail_threshold

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Drift report '{self.model_name}@{self.model_version}': "
            f"score={self.overall_score}/100 ({self.overall_status})"
        )


class DriftReportBuilder:
    """
    Builds a DriftReport from individual drift detector results.

    Parameters
    ----------
    fail_threshold : Overall score threshold above which the gate fails (default 50).
    """

    def __init__(self, fail_threshold: int = 50):
        self.fail_threshold = fail_threshold

    def build(
        self,
        model_name:       str,
        model_version:    str,
        feature_drift:    FeatureDriftReport,
        prediction_drift: PredictionDriftResult,
        importance_drift: ImportanceDriftResult,
        window_start:     str = "",
        window_end:       str = "",
    ) -> DriftReport:
        import dataclasses

        # Compute sub-scores
        feat_score  = max(
            (_STATUS_SCORE.get(r.status, 0) for r in feature_drift.results), default=0
        )
        pred_score  = _STATUS_SCORE.get(prediction_drift.status, 0)
        imp_score   = _STATUS_SCORE.get(importance_drift.status, 0)
        overall     = max(feat_score, pred_score, imp_score)

        if overall >= 100:
            status = "CRITICAL"
        elif overall >= 50:
            status = "WARNING"
        else:
            status = "OK"

        recommendations = self._recommendations(
            feature_drift, prediction_drift, importance_drift
        )

        now = datetime.now(timezone.utc).isoformat()
        return DriftReport(
            report_id        = str(uuid.uuid4()),
            timestamp        = now,
            model_name       = model_name,
            model_version    = model_version,
            window_start     = window_start or now,
            window_end       = window_end   or now,
            overall_score    = overall,
            overall_status   = status,
            feature_drift    = dataclasses.asdict(feature_drift),
            prediction_drift = dataclasses.asdict(prediction_drift),
            importance_drift = dataclasses.asdict(importance_drift),
            recommendations  = recommendations,
            overall_pass     = overall < self.fail_threshold,
        )

    @staticmethod
    def _recommendations(
        fd: FeatureDriftReport,
        pd: PredictionDriftResult,
        id_: ImportanceDriftResult,
    ) -> List[str]:
        recs = []
        if fd.critical > 0:
            critical_feats = [r.feature for r in fd.results if r.status == "CRITICAL"]
            recs.append(
                f"Investigate critical feature drift in: {', '.join(critical_feats[:5])}. "
                "Check upstream data pipeline for schema changes or data quality issues."
            )
        if pd.status in ("CRITICAL", "WARNING"):
            recs.append(
                f"Prediction distribution drift detected (JSD={pd.jsd:.3f}). "
                "Review recent deployment changes and consider model retraining."
            )
        if any(s.signal == "importance_collapse" for s in id_.signals):
            collapsed = [s.feature for s in id_.signals if s.signal == "importance_collapse"]
            recs.append(
                f"Feature importance collapse for: {', '.join(collapsed)}. "
                "This may indicate adversarial feature manipulation or pipeline failure."
            )
        if any(s.signal == "rank_inversion" for s in id_.signals):
            recs.append(
                "Significant rank inversions in top-K features. "
                "Validate that feature engineering has not changed."
            )
        if not recs:
            recs.append("No significant drift detected. Continue routine monitoring.")
        return recs
