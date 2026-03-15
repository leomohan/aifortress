"""
maturity_model.py  —  AI security maturity model definition
AI Fortress · Chapter 14 · Code Sample 14.B

Defines the maturity domains, capabilities, and scoring criteria aligned to:
  - NIST AI RMF (2023): GOVERN / MAP / MEASURE / MANAGE
  - ISO/IEC 42001:2023: AI Management System
  - NIST CSF 2.0:       GV / ID / PR / DE / RS / RC
  - EU AI Act:          High-risk system obligations (Art.9-17)

Maturity levels:
  0 = Non-existent   no process in place
  1 = Initial        ad hoc, undocumented
  2 = Developing     some documentation, inconsistently applied
  3 = Defined        documented, consistently applied
  4 = Managed        measured and monitored with metrics
  5 = Optimising     continuously improved, industry-leading
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


MATURITY_LABELS = {
    0: "Non-existent",
    1: "Initial",
    2: "Developing",
    3: "Defined",
    4: "Managed",
    5: "Optimising",
}


@dataclass
class MaturityCapability:
    capability_id:  str
    name:           str
    domain:         str
    frameworks:     List[str]      # alignment labels
    description:    str
    level_criteria: Dict[int, str] # level 1-5 → description of what that level looks like
    weight:         float = 1.0    # relative importance for domain score


# ── Domain and Capability Definitions ─────────────────────────────────────────

CAPABILITIES: List[MaturityCapability] = [

    # ── GOVERN ────────────────────────────────────────────────────────────────
    MaturityCapability(
        capability_id="GOV-01",
        name="AI Risk Policy",
        domain="Govern",
        frameworks=["NIST AI RMF GOVERN", "ISO 42001 §6", "EU AI Act Art.9"],
        description="Organisation has a documented AI risk management policy approved by leadership.",
        level_criteria={
            1: "No written policy; risks managed informally",
            2: "Draft policy exists; not formally approved",
            3: "Policy approved and published; staff awareness variable",
            4: "Policy enforced with compliance monitoring and annual review",
            5: "Policy drives continuous improvement; benchmarked against peers",
        },
        weight=1.5,
    ),
    MaturityCapability(
        capability_id="GOV-02",
        name="Roles and Accountabilities",
        domain="Govern",
        frameworks=["NIST AI RMF GOVERN", "ISO 42001 §5.3"],
        description="AI security roles (CISO, ML Security Lead, DPO, AI Ethics Lead) are defined with clear accountabilities.",
        level_criteria={
            1: "No defined roles; responsibilities unclear",
            2: "Roles informally assigned; not documented",
            3: "Roles documented in org chart and JDs; RACI exists",
            4: "Role effectiveness measured; succession planning in place",
            5: "Roles embedded in performance management; industry recognition",
        },
        weight=1.2,
    ),
    MaturityCapability(
        capability_id="GOV-03",
        name="AI Governance Committee",
        domain="Govern",
        frameworks=["NIST AI RMF GOVERN", "ISO 42001 §5.1", "EU AI Act Art.9"],
        description="A cross-functional committee oversees AI risk decisions and escalations.",
        level_criteria={
            1: "No formal committee; decisions made ad hoc",
            2: "Informal working group; irregular meetings",
            3: "Formal committee with ToR, quorum, and documented decisions",
            4: "Committee has board-level sponsor; KPIs tracked",
            5: "Committee output drives strategy; external members invited",
        },
        weight=1.0,
    ),

    # ── MAP ───────────────────────────────────────────────────────────────────
    MaturityCapability(
        capability_id="MAP-01",
        name="AI Asset Inventory",
        domain="Map",
        frameworks=["NIST AI RMF MAP", "ISO 42001 §4.1", "NIST CSF ID.AM"],
        description="All AI systems, models, and data pipelines are inventoried and classified by risk.",
        level_criteria={
            1: "No inventory; AI systems discovered reactively",
            2: "Partial list in spreadsheets; not maintained",
            3: "Formal register with owner, purpose, risk class, and data sources",
            4: "Register automated (SBOM-linked); classification reviewed quarterly",
            5: "Real-time inventory with automatic risk scoring and lineage graphs",
        },
        weight=1.5,
    ),
    MaturityCapability(
        capability_id="MAP-02",
        name="Algorithmic Impact Assessment",
        domain="Map",
        frameworks=["NIST AI RMF MAP", "EU AI Act Art.9", "GDPR Art.35"],
        description="AIAs and DPIAs are conducted before deploying systems that affect individuals.",
        level_criteria={
            1: "No AIA process; systems deployed without impact review",
            2: "AIAs conducted on request; no standard template",
            3: "AIA mandatory gate with template; DPO reviews high-risk systems",
            4: "AIA outcomes tracked to closure; re-assessment on material change",
            5: "AIA integrated into CI/CD; outcomes feed risk management system",
        },
        weight=1.5,
    ),
    MaturityCapability(
        capability_id="MAP-03",
        name="Threat Modelling for AI",
        domain="Map",
        frameworks=["NIST AI RMF MAP", "NIST CSF ID.RA"],
        description="AI-specific threat modelling (STRIDE, LINDDUN) applied to new and existing systems.",
        level_criteria={
            1: "No threat modelling for AI systems",
            2: "General IT threat modelling applied ad hoc to AI",
            3: "AI-specific STRIDE threat models produced for all high-risk systems",
            4: "Threat models reviewed against current threat intelligence quarterly",
            5: "Adversarial ML threat library maintained; red team exercises run",
        },
        weight=1.2,
    ),

    # ── MEASURE ───────────────────────────────────────────────────────────────
    MaturityCapability(
        capability_id="MEA-01",
        name="Model Performance Monitoring",
        domain="Measure",
        frameworks=["NIST AI RMF MEASURE", "EU AI Act Art.12", "ISO 42001 §9.1"],
        description="Production models are continuously monitored for accuracy, drift, and fairness.",
        level_criteria={
            1: "No production monitoring; model quality assessed only at launch",
            2: "Manual sampling checks; no automated alerts",
            3: "Automated drift and accuracy monitoring with alert thresholds",
            4: "Fairness metrics monitored; SLOs defined and tracked",
            5: "Self-healing pipelines; automated retraining on drift detection",
        },
        weight=1.5,
    ),
    MaturityCapability(
        capability_id="MEA-02",
        name="Security Testing of AI Systems",
        domain="Measure",
        frameworks=["NIST AI RMF MEASURE", "EU AI Act Art.15", "NIST CSF PR.AT"],
        description="Regular adversarial robustness testing, red-team exercises, and penetration testing.",
        level_criteria={
            1: "No security testing specific to AI systems",
            2: "Annual pen test includes AI APIs; adversarial testing not planned",
            3: "Adversarial robustness tests in CI/CD; annual AI red-team exercise",
            4: "Continuous adversarial testing; results fed into model hardening",
            5: "Bug bounty covers AI systems; adversarial ML research program",
        },
        weight=1.3,
    ),
    MaturityCapability(
        capability_id="MEA-03",
        name="Fairness and Bias Evaluation",
        domain="Measure",
        frameworks=["NIST AI RMF MEASURE", "EU AI Act Art.10", "IEEE 7000-2021"],
        description="Quantitative fairness metrics computed pre-deployment and monitored in production.",
        level_criteria={
            1: "No fairness evaluation; bias treated as non-technical",
            2: "Ad hoc fairness review at launch; no production monitoring",
            3: "Standard fairness metrics computed pre-deployment; thresholds set",
            4: "Production parity tracking with automated alerts; AIA updated",
            5: "Intersectional analysis; fairness research published; external audit",
        },
        weight=1.2,
    ),

    # ── MANAGE ────────────────────────────────────────────────────────────────
    MaturityCapability(
        capability_id="MAN-01",
        name="Incident Response for AI",
        domain="Manage",
        frameworks=["NIST AI RMF MANAGE", "NIST CSF RS", "EU AI Act Art.73"],
        description="AI-specific IR plan exists with playbooks, roles, and tested response procedures.",
        level_criteria={
            1: "General IT IR plan; no AI-specific procedures",
            2: "AI incidents handled under IT IR plan with no AI playbooks",
            3: "AI IRP with playbooks for key categories; tested annually",
            4: "Tabletop exercises run; metrics (TTD/TTC/TTR) tracked and improving",
            5: "Automated containment for known attack patterns; ISAC membership",
        },
        weight=1.5,
    ),
    MaturityCapability(
        capability_id="MAN-02",
        name="Supply Chain Security for AI",
        domain="Manage",
        frameworks=["NIST AI RMF MANAGE", "NIST CSF ID.SC", "EU AI Act Art.13"],
        description="Third-party models, datasets, and ML libraries assessed before use.",
        level_criteria={
            1: "Pre-trained models used without security assessment",
            2: "Informal review of major third-party components",
            3: "Mandatory SBOM and provenance check for all third-party AI components",
            4: "Continuous dependency scanning; trust policy enforced in CI/CD",
            5: "Supplier security programme; contractual AI security requirements",
        },
        weight=1.3,
    ),
    MaturityCapability(
        capability_id="MAN-03",
        name="Data Governance for AI",
        domain="Manage",
        frameworks=["NIST AI RMF MANAGE", "EU AI Act Art.10", "GDPR Art.5"],
        description="Training and inference data is governed for quality, provenance, and privacy.",
        level_criteria={
            1: "No data governance; training data sourced and used without controls",
            2: "Data owners identified; no formal quality or lineage standards",
            3: "Data quality gates, provenance logging, and PII scanning in pipelines",
            4: "Lineage graph maintained; automated bias and contamination detection",
            5: "Federated learning and differential privacy used where appropriate",
        },
        weight=1.3,
    ),
    MaturityCapability(
        capability_id="MAN-04",
        name="Explainability and Transparency",
        domain="Manage",
        frameworks=["NIST AI RMF MANAGE", "EU AI Act Art.13", "GDPR Art.22"],
        description="Meaningful explanations available for automated decisions; model cards published.",
        level_criteria={
            1: "No explanations; decisions treated as black box",
            2: "Feature importance available internally; not surfaced to end users",
            3: "Explanation API available; model cards published for high-risk systems",
            4: "Explanation quality audited; right-to-explanation workflow tested",
            5: "Standardised explanation format across all models; third-party audits",
        },
        weight=1.2,
    ),
]

DOMAINS = list(dict.fromkeys(c.domain for c in CAPABILITIES))
