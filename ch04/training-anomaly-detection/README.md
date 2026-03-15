# Ch.04-B — Training Anomaly Detection

**AI Fortress** · Chapter 4: Secure Training Environment

---

## What This Does

Real-time training telemetry monitoring pipeline that detects adversarial
manipulation of the training process:

- **Loss spike detector** — monitors per-step and per-epoch loss curves for
  statistically anomalous spikes (Z-score and IQR methods); sudden unexplained
  spikes can indicate poisoned batches reaching the model
- **Gradient norm monitor** — tracks the L2 norm of gradients per parameter
  group; exploding gradients can indicate adversarial weight injection or
  corrupted optimiser states; vanishing gradients can signal backdoor activity
- **Learning rate schedule auditor** — verifies that the actual learning rate
  each step matches the declared schedule; schedule manipulation is a subtle
  attack vector on optimiser state
- **Checkpoint integrity verifier** — computes a SHA-256 hash of every saved
  checkpoint and verifies it against a signed manifest before resuming training;
  detects adversarial checkpoint injection mid-run
- **Telemetry aggregator** — collects all anomaly findings into a structured
  event log, suitable for streaming to SIEM (Splunk, Datadog, etc.)

---

## File Structure

```
training-anomaly-detection/
├── README.md
├── requirements.txt
├── loss_spike_detector.py        # Step/epoch loss anomaly detection
├── gradient_norm_monitor.py      # Gradient norm surveillance
├── lr_schedule_auditor.py        # Learning rate schedule verification
├── checkpoint_integrity.py       # Checkpoint hash manifest and verifier
├── telemetry_aggregator.py       # SIEM-ready event log aggregator
└── tests/
    └── test_training_anomaly.py
```

## Quick Start

```python
from loss_spike_detector import LossSpikeDetector
from checkpoint_integrity import CheckpointIntegrityManager

# Monitor loss during training
detector = LossSpikeDetector(window=50, z_threshold=3.5)
for step, loss in enumerate(training_losses):
    finding = detector.observe(step=step, loss=loss)
    if finding:
        print(f"ANOMALY at step {step}: {finding.description}")

# Sign checkpoint after saving
mgr = CheckpointIntegrityManager(manifest_path="checkpoints/manifest.json")
mgr.register("checkpoints/epoch_01.pt")

# Verify before resuming
mgr.verify_all()   # raises CheckpointTamperError if any hash mismatches
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
