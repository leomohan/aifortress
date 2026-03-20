# Ch.13-A — DP-SGD Training with Opacus

**AI Fortress** · Chapter 13: Privacy-Preserving Machine Learning

---

## What This Does

Implements differentially private stochastic gradient descent (DP-SGD)
training using the Opacus library, with supporting infrastructure for
privacy budget tracking and auditing:

- **Privacy engine wrapper** — wraps Opacus `PrivacyEngine` to attach
  differential privacy to any PyTorch model; records noise multiplier,
  max gradient norm (clip bound), and sample rate; provides a clean
  `attach()` / `detach()` lifecycle; computes spent epsilon after each
  training step using the Rényi Differential Privacy (RDP) accountant
- **Privacy budget tracker** — maintains a per-model privacy budget
  register; records epsilon/delta spent per epoch; raises
  `BudgetExhaustedError` when the configured (ε, δ) budget is consumed;
  supports multiple concurrent model training runs
- **Per-sample gradient clipper** — standalone implementation of
  per-sample gradient L2 norm clipping (the core DP-SGD primitive)
  without requiring Opacus; useful for custom training loops and
  educational demonstration of the mechanism
- **Privacy accountant** — moment accountant for (ε, δ)-DP composition
  using the simplified RDP → (ε, δ) conversion formula; tracks
  composition across multiple training steps; provides a budget
  remaining estimate

---

## File Structure

```
dp-sgd-opacus/
├── README.md
├── requirements.txt
├── privacy_engine_wrapper.py   # Opacus PrivacyEngine lifecycle wrapper
├── privacy_budget_tracker.py   # Per-model (ε, δ) budget register
├── gradient_clipper.py         # Per-sample gradient clipping (pure Python)
├── privacy_accountant.py       # RDP moment accountant
└── tests/
    └── test_dp_sgd.py
```

## Dependencies

```bash
pip install torch opacus  # for full DP-SGD; not required for tests
```
