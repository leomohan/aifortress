# AI Fortress — Chapter 13 Code Resources
## Privacy-Preserving Machine Learning

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Modo Bhaik  
**Chapter:** 13 of 17

---

## Resources in This Package

| ID | Folder | Type | Description |
|----|--------|------|-------------|
| 13.A | `dp-sgd-opacus/` | Code | DP-SGD training with Opacus: privacy engine wrapper, epsilon/delta budget tracker, per-sample gradient clipper, and privacy accountant |
| 13.B | `fl-dp-flower/` | Code | Federated learning with differential privacy via Flower: DP-enabled server aggregation strategy, client privacy wrapper, round budget tracker |
| 13.C | `dp-synthetic-data/` | Code | Differentially private synthetic data generation: Gaussian mechanism tabular synthesiser, privacy parameter selector, fidelity evaluator |
| 13.D | `privacy-audit-suite/` | Code | Privacy audit tooling: membership inference attack simulator, attribute inference risk scorer, canary insertion auditor, audit report generator |
| 13.E | `privacy-preserving-inference/` | Code | Privacy-safe inference: output perturbation with calibrated noise, prediction confidence suppressor, k-anonymity response checker |
| 13.F | `dpia-privacy-budget-templates/` | Templates | DPIA worksheet, privacy budget register, and data processing record templates |

---

## Quick Setup (each code resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

> **Note on optional dependencies**: `dp-sgd-opacus` requires `torch` and
> `opacus`. `fl-dp-flower` requires `flwr`. These are listed in requirements.txt
> but heavy to install; all core logic is tested with lightweight stubs so the
> test suite runs without GPU or network access.

---

## Privacy Threat Taxonomy (Chapter 13)

1. Membership inference — attacker determines whether a record was in training data
2. Attribute inference — attacker reconstructs sensitive attributes from predictions
3. Model inversion — attacker reconstructs training inputs from gradients or outputs
4. Gradient leakage in federated learning — raw gradients reveal individual records
5. Synthetic data re-identification — generated records linked back to real individuals
6. Over-confident outputs revealing training membership
7. Missing DPIA for high-risk processing operations
8. Privacy budget exhaustion without tracking

---

## Companion Site

**https://[your-domain]/resources/ch13**

---

*© AI Fortress · Modo Bhaik. For educational and professional use.*
