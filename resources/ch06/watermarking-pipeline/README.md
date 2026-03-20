# Ch.06-B — Watermarking Pipeline

**AI Fortress** · Chapter 6: Model Encryption, Signing & IP Protection

---

## What This Does

Three complementary watermarking schemes for establishing model and dataset ownership:

- **Radioactive data watermarking** — embeds an imperceptible statistical
  signal into a subset of training samples before training. If an attacker
  trains a model on the watermarked dataset, their model will exhibit a
  detectable bias on a held-out verification set. Follows Maini et al. 2021.
  Works without modifying the model; only requires access to the training data.
- **Weight perturbation watermark** — embeds a secret bit-string into model
  weights by slightly perturbing selected parameters. The watermark survives
  fine-tuning and weight pruning up to moderate levels. Uses a keyed PRNG to
  select the target weight indices — only the holder of the secret key can
  verify or extract the watermark.
- **Output watermarking** — embeds a statistical signal into the model's
  outputs at inference time (lexical substitution / synonym selection steered
  by a secret key). The watermark is detectable by statistical hypothesis
  test on a sample of outputs, but imperceptible to individual users.
  Suitable for text-generation and classification APIs.

---

## File Structure

```
watermarking-pipeline/
├── README.md
├── requirements.txt
├── radioactive_data.py         # Dataset-level radioactive watermarking
├── weight_watermark.py         # Weight perturbation watermark embed/verify
├── output_watermark.py         # Inference-time output watermarking
└── tests/
    └── test_watermarking.py
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
