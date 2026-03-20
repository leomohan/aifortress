# AI Fortress — Chapter 6 Code Resources
## Model Encryption, Signing & IP Protection

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 6 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 6.A | `model-encryption-signing/` | Encrypt model weights at rest and in transit; sign model artefacts with Ed25519; verify signatures before loading; key management and rotation |
| 6.B | `watermarking-pipeline/` | Embed and verify dataset and model watermarks: radioactive data watermarking, model weight perturbation watermarks, and inference-time output watermarking |
| 6.C | `ip-protection-toolkit/` | Intellectual property protection: model fingerprinting, ownership verification via black-box API queries, dataset membership inference defence, and licence enforcement |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 6)

1. Model weight theft (exfiltration of checkpoint files)
2. Unauthorised redistribution of trained models
3. Model cloning via knowledge distillation from API
4. Training data reconstruction from model weights
5. IP laundering (fine-tuning to erase ownership signals)
6. Reverse engineering of model architecture
7. Checkpoint injection (replacing weights with backdoored copy)
8. Side-channel weight exfiltration during inference
9. Dataset provenance disputes (who owns the training data)
10. Licence circumvention (deploying model beyond agreed scope)

---

## Companion Site

**https://[your-domain]/resources/ch06**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
