# Ch.13-B — Federated Learning with Differential Privacy (Flower)

**AI Fortress** · Chapter 13: Privacy-Preserving Machine Learning

---

## What This Does

Implements differentially private federated learning using the Flower
(flwr) framework:

- **DP server aggregation strategy** — wraps Flower's FedAvg with
  server-side DP: clips client model updates to a global L2 bound,
  adds calibrated Gaussian noise to the aggregate, and enforces
  minimum client participation thresholds to satisfy DP amplification
- **Client privacy wrapper** — adds local DP to individual client
  training; records per-round epsilon spending and blocks participation
  when the local budget is exceeded
- **Round budget tracker** — tracks total privacy budget consumed
  across federated rounds; each round's epsilon is computed from
  the per-round noise scale and participation rate; warns when
  approaching the global budget limit

---

## File Structure

```
fl-dp-flower/
├── README.md
├── requirements.txt
├── dp_aggregation_strategy.py  # DP-FedAvg server-side aggregation
├── client_privacy_wrapper.py   # Local DP client wrapper
├── round_budget_tracker.py     # Per-round federated DP budget accounting
└── tests/
    └── test_fl_dp.py
```

## Dependencies

```bash
pip install flwr  # for full federated learning; not required for tests
```
