# Ch.05-A — ML API Hardening

**AI Fortress** · Chapter 5: API Hardening & Adversarial Defence

---

## What This Does

Production security layer for ML inference APIs, covering five controls:

- **Rate limiter** — sliding-window and token-bucket rate limiting per API key,
  IP address, and user tier; backs off with Retry-After headers; logs burst
  events for abuse detection; pluggable storage backend (in-memory / Redis)
- **Input validator** — schema-enforced validation of inference request payloads;
  checks tensor shape, dtype, value range, and sequence length; rejects
  malformed inputs that could cause OOM or trigger undefined model behaviour;
  enforces per-endpoint input budgets to prevent DoS via expensive inputs
- **Output sanitiser** — scrubs model outputs before returning to callers:
  suppresses raw confidence scores above a threshold (membership inference
  defence), redacts PII patterns, enforces output length limits, and flags
  high-entropy outputs that may contain model-internal data
- **Authentication middleware** — API key validation with scope checking,
  key rotation support, and per-key rate limit tiers; generates structured
  auth audit events for every request
- **Abuse detector** — analyses request patterns to identify model extraction
  (systematic boundary probing), membership inference attempts (confidence
  fishing), and DDoS patterns; emits alerts and can auto-block offending keys

---

## File Structure

```
api-hardening/
├── README.md
├── requirements.txt
├── rate_limiter.py            # Sliding-window and token-bucket rate limiting
├── input_validator.py         # Inference request schema validation
├── output_sanitiser.py        # Response scrubbing and confidence suppression
├── auth_middleware.py         # API key auth, scopes, and audit logging
├── abuse_detector.py          # Extraction and membership inference detection
└── tests/
    └── test_api_hardening.py
```

## Quick Start

```python
from rate_limiter import RateLimiter, RateLimitExceeded
from input_validator import InputValidator, InputSpec
from output_sanitiser import OutputSanitiser

# Rate limiting
limiter = RateLimiter(requests_per_minute=60)
try:
    limiter.check(key="api-key-abc")
except RateLimitExceeded as e:
    return 429, {"error": str(e), "retry_after": e.retry_after}

# Input validation
spec    = InputSpec(max_tokens=512, allowed_dtypes=["float32"], max_shape=[1, 3, 224, 224])
payload = {"input": tensor_data}
validator.validate(payload, spec)   # raises InputValidationError on failure

# Output sanitisation
sanitiser = OutputSanitiser(suppress_confidence_above=0.95)
safe_out  = sanitiser.sanitise(raw_model_output)
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
