# AI Fortress — Chapter 5 Code Resources
## API Hardening & Adversarial Defence

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Modo Bhaik  
**Chapter:** 5 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 5.A | `api-hardening/` | Production ML API security: rate limiting, input validation, output sanitisation, authentication middleware, and abuse detection |
| 5.B | `adversarial-defence/` | Adversarial example detection and certified robustness: input smoothing, feature squeezing, FGSM/PGD attack simulation, and robustness evaluation |
| 5.C | `prompt-injection-classifier/` | Prompt injection and jailbreak detection for LLM-serving APIs: pattern-based, embedding-based, and heuristic detectors with quarantine pipeline |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 5)

1. Evasion attacks (adversarial examples at inference)
2. Model extraction via API queries
3. Membership inference via confidence scores
4. Prompt injection and indirect prompt injection
5. Jailbreaking and goal hijacking (LLMs)
6. Denial-of-service via expensive inference inputs
7. Timing side-channel attacks on model structure
8. Input-space boundary probing
9. Output manipulation via adversarial suffixes
10. API key theft and credential stuffing

---

## Companion Site

**https://[your-domain]/resources/ch05**

---

*© AI Fortress · Modo Bhaik. For educational and professional use.*
