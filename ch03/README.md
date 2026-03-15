# AI Fortress — Chapter 3 Code Resources
## Data Quality & Contamination

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Modo Bhaik  
**Chapter:** 3 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 3.A | `contamination-detection/` | Statistical detection of poisoning, backdoor triggers, label flipping, and distribution shift in training datasets |
| 3.B | `label-validation-pipeline/` | Multi-method label auditing: inter-annotator agreement, confidence-based cleaning, noise-rate estimation, and golden-set validation |
| 3.C | `data-quality-dashboard/` | Automated data quality scoring, drift detection, schema validation, and anomaly flagging across ML pipeline stages |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

Each folder contains its own `README.md` with full usage instructions.

---

## Threat Taxonomy Covered (Chapter 3)

1. Label-flipping poisoning
2. Backdoor / trojan trigger injection
3. Gradient-based targeted poisoning
4. Clean-label poisoning
5. Data distribution shift
6. Feature-space contamination
7. Duplicate and near-duplicate injection
8. Schema drift and type corruption
9. Statistical outlier injection
10. Annotator bias and systematic labelling errors

---

## Companion Site

**https://[your-domain]/resources/ch03**

---

*© AI Fortress · Modo Bhaik. For educational and professional use.*
