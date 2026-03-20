"""
label_audit_report.py  —  Label audit report generator
AI Fortress · Chapter 3 · Code Sample 3.B
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from iaa_calculator import IAAResult
from confidence_cleaner import CleaningResult
from noise_rate_estimator import NoiseRateResult
from golden_set_validator import GoldenValidationResult, AnnotatorTrustScore


@dataclass
class LabelAuditReport:
    dataset_id:        str
    generated_at:      str = ""
    iaa_results:       List[dict] = field(default_factory=list)
    cleaning_result:   Optional[dict] = None
    noise_rate_result: Optional[dict] = None
    golden_result:     Optional[dict] = None
    annotator_scores:  List[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_iaa(self, result: IAAResult) -> None:
        self.iaa_results.append(asdict(result))

    def add_cleaning(self, result: CleaningResult) -> None:
        self.cleaning_result = asdict(result)

    def add_noise_rate(self, result: NoiseRateResult) -> None:
        self.noise_rate_result = asdict(result)

    def add_golden_validation(self, result: GoldenValidationResult) -> None:
        self.golden_result = asdict(result)

    def add_annotator_scores(self, scores: List[AnnotatorTrustScore]) -> None:
        self.annotator_scores = [asdict(s) for s in scores]

    def to_json(self, path: Optional[str | Path] = None) -> str:
        text = json.dumps(asdict(self), indent=2)
        if path:
            Path(path).write_text(text, encoding="utf-8")
        return text

    def to_markdown(self, path: Optional[str | Path] = None) -> str:
        lines = [
            f"# Label Audit Report — {self.dataset_id}",
            f"**Generated:** {self.generated_at}",
            "",
        ]

        # IAA section
        if self.iaa_results:
            lines += ["## Inter-Annotator Agreement", ""]
            for r in self.iaa_results:
                icon = "✅" if r["value"] >= 0.61 else ("⚠️" if r["value"] >= 0.41 else "❌")
                lines.append(f"- **{r['metric']}**: {r['value']:.3f} {icon} — {r['interpretation']} ({r['n_samples']} samples)")
            lines.append("")

        # Cleaning section
        if self.cleaning_result:
            cr = self.cleaning_result
            pct = cr["noise_rate"] * 100
            icon = "✅" if pct < 2 else ("⚠️" if pct < 5 else "❌")
            lines += [
                "## Confidence-Based Label Cleaning", "",
                f"- Suspected mislabels: **{len(cr['noisy_indices'])}** / {cr['n_samples']} {icon} ({pct:.1f}%)",
                f"- Classifier: {cr['details'].get('classifier', 'N/A')}, {cr['details'].get('n_splits')} folds",
            ]
            if cr["per_class_noise"]:
                lines.append("\n**Per-class noise estimates:**")
                for cls, info in sorted(cr["per_class_noise"].items()):
                    pct_c = info["noise_rate"] * 100
                    lines.append(f"  - `{cls}`: {pct_c:.1f}% ({info['noisy']}/{info['total']})")
            lines.append("")

        # Noise rate section
        if self.noise_rate_result:
            nr = self.noise_rate_result
            lines += [
                "## Noise Rate Estimation (Confident Learning)", "",
                f"- Global estimated noise rate: **{nr['global_noise_rate']*100:.1f}%**",
                "",
                "**Per-class estimated noise:**",
            ]
            for cls, rate in sorted(nr["per_class_noise"].items()):
                lines.append(f"  - `{cls}`: {rate*100:.1f}%")
            lines.append("")

        # Golden set section
        if self.golden_result:
            gv = self.golden_result
            icon = "✅" if gv["accuracy"] >= 0.9 else ("⚠️" if gv["accuracy"] >= 0.75 else "❌")
            lines += [
                "## Golden-Set Validation", "",
                f"- Accuracy: **{gv['accuracy']*100:.1f}%** {icon}",
                f"- Weighted F1: **{gv['weighted_f1']:.3f}**",
                f"- Samples compared: {gv['n_compared']}",
                "",
                "**Per-class performance:**",
                "| Class | Precision | Recall | F1 | Support |",
                "|-------|-----------|--------|----|---------|",
            ]
            for cls, m in sorted(gv["per_class_metrics"].items()):
                lines.append(
                    f"| `{cls}` | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['support']} |"
                )
            lines.append("")

        # Annotator scores
        if self.annotator_scores:
            lines += [
                "## Annotator Trust Scores", "",
                "| Annotator | Trust Score | Accuracy | Gold Submitted | Weak Classes |",
                "|-----------|------------|----------|----------------|--------------|",
            ]
            for s in sorted(self.annotator_scores, key=lambda x: x["trust_score"]):
                weak = ", ".join(s["weak_classes"]) or "—"
                icon = "✅" if s["trust_score"] >= 0.85 else ("⚠️" if s["trust_score"] >= 0.70 else "❌")
                lines.append(
                    f"| {s['annotator_id']} {icon} | {s['trust_score']:.3f} | {s['accuracy']:.3f} | {s['n_gold_submitted']} | {weak} |"
                )
            lines.append("")

        text = "\n".join(lines)
        if path:
            Path(path).write_text(text, encoding="utf-8")
        return text
