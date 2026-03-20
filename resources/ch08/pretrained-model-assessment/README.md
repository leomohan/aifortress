# Ch.08-C — Pretrained Model Security Assessment

**AI Fortress** · Chapter 8: Software Supply Chain Security for ML

---

## What This Does

Security assessment of pretrained models from public registries:

- **Pickle safety scanner** — detects dangerous opcodes in `.pkl` / `.pt` /
  `.pth` checkpoint files before loading; maps opcode sequences to known
  exploit patterns (arbitrary code execution via `__reduce__`, `exec`,
  `eval`, `os.system`); produces a safety verdict and refuses load on failure
- **Weight integrity verifier** — verifies SHA-256 checksums of model weight
  files against a manifest (from HuggingFace `pytorch_model.bin.index.json`
  or a custom manifest); detects partial downloads, truncated files, and
  weight file substitution attacks
- **Model card scorer** — scores the completeness of a model card against
  the AI Fortress model card standard (25 fields across 5 categories:
  identity, training data, evaluation, limitations, governance); penalises
  missing mandatory fields; produces a completeness score (0–100) and flags
  models with incomplete governance documentation

---

## File Structure

```
pretrained-model-assessment/
├── README.md
├── requirements.txt
├── pickle_safety_scanner.py    # Pickle opcode analysis before model load
├── weight_integrity_verifier.py # SHA-256 manifest verification
├── model_card_scorer.py        # Model card completeness scoring
└── tests/
    └── test_pretrained_assessment.py
```
