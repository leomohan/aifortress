# Ch.09-A — ML API Gateway Security

**AI Fortress** · Chapter 9: Network Security & Zero-Trust for ML Infrastructure

---

## What This Does

Hardens the ML API gateway layer against authentication bypass, request
tampering, and abuse:

- **JWT authenticator** — validates HS256/RS256 JWTs for ML API requests;
  enforces audience, issuer, expiry, and required scope claims; applies a
  strict algorithm allowlist (rejects `alg: none`); produces structured
  AuthResult with principal identity and granted scopes
- **API key manager** — HMAC-SHA256 hashed key storage (never stores raw
  keys); key metadata with owner, scopes, expiry, and rate-limit tier;
  constant-time comparison; key rotation with configurable grace period;
  structured key audit log
- **Request signing verifier** — verifies HMAC-SHA256 request signatures
  over method + path + timestamp + body hash; enforces a 5-minute replay
  window; rejects requests with missing or stale timestamps
- **IP policy enforcer** — allowlist and denylist enforcement with CIDR
  support; geo-block stubs; per-endpoint IP policy; structured deny log
- **Security audit logger** — structured JSON Lines audit trail for all
  gateway decisions (auth pass/fail, rate limit, signing fail, IP deny);
  tamper-evident chaining with SHA-256 rolling hash

---

## File Structure

```
api-gateway-security/
├── README.md
├── requirements.txt
├── jwt_authenticator.py        # JWT validation with scope enforcement
├── api_key_manager.py          # Hashed API key lifecycle and audit
├── request_signing_verifier.py # HMAC-SHA256 request signature verification
├── ip_policy_enforcer.py       # CIDR-based IP allowlist/denylist
├── security_audit_logger.py    # Structured audit trail with tamper chaining
└── tests/
    └── test_api_gateway.py
```
