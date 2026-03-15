# Ch.11-C — Automated Access Review

**AI Fortress** · Chapter 11: Identity & Access Management for ML Infrastructure

---

## What This Does

Automates periodic access review campaigns for ML infrastructure entitlements:

- **Stale entitlement detector** — identifies accounts with no recorded
  activity within a configurable lookback window (default 90 days);
  flags service accounts with excessive permissions relative to their
  typical usage pattern; produces a stale entitlement report with
  recommended actions (revoke, review, retain)
- **Peer-group anomaly detector** — compares each user's permission set
  against their peer group (same team/role); flags users with significantly
  more permissions than the group median; uses Jaccard distance for
  permission-set comparison; severity tiers based on deviation magnitude
- **Review workflow engine** — manages the access review campaign lifecycle
  (create campaign, assign reviewers, record certify/revoke decisions,
  generate remediation list); tracks review completion percentage;
  escalates unanswered reviews past deadline
- **Access certification report** — produces a structured compliance report
  summarising the campaign: total entitlements reviewed, certified, revoked,
  and pending; sign-off metadata for audit evidence

---

## File Structure

```
access-review-automation/
├── README.md
├── requirements.txt
├── stale_entitlement_detector.py   # Inactivity-based stale access detection
├── peer_group_anomaly.py           # Peer-comparison permission anomaly detection
├── review_workflow.py              # Campaign lifecycle and reviewer workflow
├── access_certification_report.py  # Compliance certification report
└── tests/
    └── test_access_review.py
```
