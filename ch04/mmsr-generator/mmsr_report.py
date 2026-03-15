"""
mmsr_report.py  —  MMSR assembler and signed report generator
AI Fortress · Chapter 4 · Code Sample 4.C

Assembles a Model and ML System Report (MMSR) from all evidence sources
and outputs signed JSON + Markdown documents.
"""
from __future__ import annotations
import hashlib, json, uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from training_config import TrainingConfig
from compute_provenance import ComputeProvenance
from data_lineage import DataLineage
from security_controls import SecurityControlsEvidence, CHAPTER4_CONTROLS


@dataclass
class MMSRReport:
    report_id:        str
    generated_at:     str
    config:           dict
    provenance:       dict
    lineage:          dict
    controls:         list
    coverage_score:   float
    unattested:       list
    security_gaps:    list
    sha256:           str = ""

    @classmethod
    def build(
        cls,
        config:    TrainingConfig,
        provenance: ComputeProvenance,
        lineage:   DataLineage,
        controls:  SecurityControlsEvidence,
    ) -> "MMSRReport":
        now       = datetime.now(timezone.utc).isoformat()
        report_id = str(uuid.uuid4())

        obj = cls(
            report_id      = report_id,
            generated_at   = now,
            config         = config.to_dict(),
            provenance     = provenance.to_dict(),
            lineage        = lineage.to_dict(),
            controls       = controls.to_list(),
            coverage_score = round(controls.coverage_score(), 4),
            unattested     = controls.unattest(),
            security_gaps  = config.security_gaps(),
        )
        payload    = json.dumps(
            {k: v for k, v in obj.__dict__.items() if k != "sha256"}, sort_keys=True
        )
        obj.sha256 = hashlib.sha256(payload.encode()).hexdigest()
        return obj

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")

    def save_markdown(self, path: str | Path) -> None:
        Path(path).write_text(self._to_markdown(), encoding="utf-8")

    def _to_markdown(self) -> str:
        cfg = self.config
        prv = self.provenance
        lin = self.lineage
        cov_pct = self.coverage_score * 100
        cov_icon = "✅" if cov_pct >= 80 else ("⚠️" if cov_pct >= 50 else "❌")

        lines = [
            f"# Model and ML System Report (MMSR)",
            f"**Report ID:** `{self.report_id}`  ",
            f"**Generated:** {self.generated_at}  ",
            f"**SHA-256:** `{self.sha256}`",
            "",
            "---",
            "",
            "## 1. Model Identity",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Model Name | {cfg.get('model_name','')} |",
            f"| Version | {cfg.get('model_version','')} |",
            f"| Task Type | {cfg.get('task_type','')} |",
            f"| Architecture | {cfg.get('architecture','—')} |",
            f"| Parameters | {cfg.get('n_parameters','—')} |",
            "",
            "## 2. Training Configuration",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Framework | {cfg.get('framework','')} {cfg.get('framework_version','')} |",
            f"| Python | {cfg.get('python_version','')} |",
            f"| Epochs | {cfg.get('epochs','—')} |",
            f"| Batch Size | {cfg.get('batch_size','—')} |",
            f"| Learning Rate | {cfg.get('learning_rate','—')} |",
            f"| Optimizer | {cfg.get('optimizer','—')} |",
            f"| Loss Function | {cfg.get('loss_function','—')} |",
            f"| Random Seed | {cfg.get('random_seed','⚠️ NOT SET')} |",
            f"| Gradient Clipping | {cfg.get('gradient_clipping','⚠️ NOT SET')} |",
            f"| Mixed Precision | {cfg.get('mixed_precision', False)} |",
            "",
            "## 3. Compute Provenance",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Job ID | {prv.get('job_id','')} |",
            f"| Started | {prv.get('started_at','')} |",
            f"| Completed | {prv.get('completed_at','—')} |",
            f"| Hostname | {prv.get('hostname','')} |",
            f"| Platform | {prv.get('os_platform','')} |",
            f"| GPUs | {prv.get('gpu_count','0')} × {prv.get('gpu_model','—')} |",
            f"| Cloud | {prv.get('cloud_provider','on-prem')} {prv.get('cloud_region','')} |",
            f"| Network Isolated | {'✅' if prv.get('network_isolated') else '❌'} |",
            f"| GPU Hygiene | {'✅' if prv.get('gpu_hygiene_cert') else '❌'} {prv.get('gpu_hygiene_cert','')} |",
            f"| Workspace Wiped | {'✅' if prv.get('workspace_wiped') else '❌'} |",
            "",
            "## 4. Data Lineage",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Dataset ID | {lin.get('dataset_id','')} |",
            f"| Version | {lin.get('dataset_version','')} |",
            f"| SHA-256 | `{lin.get('dataset_sha256','—')}` |",
            f"| Train / Val / Test | {lin.get('n_train','?')} / {lin.get('n_val','?')} / {lin.get('n_test','?')} |",
            f"| Anonymised | {'✅' if lin.get('anonymisation_applied') else '❌'} |",
            f"| GDPR Basis | {lin.get('gdpr_lawful_basis','—')} |",
            f"| DPIA Reference | {lin.get('dpia_ref','—')} |",
            "",
            "## 5. Security Controls",
            f"**Coverage score: {cov_pct:.0f}% {cov_icon}**",
            "",
            "| Control | Status | Evidence |",
            "|---------|--------|----------|",
        ]
        attested_map = {c["control_name"]: c for c in self.controls}
        for ctrl in CHAPTER4_CONTROLS:
            if ctrl in attested_map:
                a    = attested_map[ctrl]
                icon = "✅" if a["active"] else "❌"
                ref  = a.get("evidence_ref", "—") or "—"
            else:
                icon = "⚠️"
                ref  = "not attested"
            lines.append(f"| `{ctrl}` | {icon} | {ref} |")

        if self.security_gaps:
            lines += ["", "### ⚠️ Security Gaps"]
            for gap in self.security_gaps:
                lines.append(f"- {gap}")

        if self.unattested:
            lines += ["", "### Unattested Controls"]
            for ctrl in self.unattested:
                lines.append(f"- `{ctrl}` — not attested in this report")

        lines += [
            "",
            "---",
            f"*This MMSR was generated by AI Fortress Chapter 4 tooling.*  ",
            f"*Tamper-evident SHA-256: `{self.sha256}`*",
        ]
        return "\n".join(lines)
