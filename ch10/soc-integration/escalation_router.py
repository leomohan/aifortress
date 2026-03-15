"""
escalation_router.py  —  Alert escalation routing for ML security events
AI Fortress · Chapter 10 · Code Sample 10.B

Routes triaged ML security alerts to the correct response channels based
on priority, team ownership, and time-of-day on-call schedule.

Supported channels (stub implementations — replace with real integrations):
  slack      → POST to Slack incoming webhook
  pagerduty  → PagerDuty Events API v2 trigger
  email      → SMTP send stub
  ticket     → Jira/ServiceNow ticket creation stub

Routing matrix (configurable):
  P1 → slack + pagerduty  (immediate, 24/7)
  P2 → slack + ticket     (business hours) / + pagerduty (out of hours)
  P3 → ticket             (next business day)
  P4 → log only
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from alert_triage import TriageDecision


@dataclass
class RoutingResult:
    event_id:   str
    priority:   str
    channels:   List[str]        # channels routed to
    success:    List[str]        # channels that accepted
    failed:     List[str]        # channels that errored
    detail:     str


@dataclass
class ChannelConfig:
    name:       str
    handler:    Callable         # fn(decision, payload) → bool
    priorities: List[str]        # P-levels that use this channel
    enabled:    bool = True


_DEFAULT_PAYLOAD_TEMPLATE = (
    "[{priority}] {event_type} | {action}\n"
    "Rule: {matched_rule} | Confidence: {confidence:.0%}\n"
    "Detail: {detail}"
)


class EscalationRouter:
    """
    Routes triage decisions to the appropriate response channels.

    Parameters
    ----------
    channels   : List of ChannelConfig objects.
    audit_path : Optional JSON Lines log of routing results.
    """

    def __init__(
        self,
        channels:   Optional[List[ChannelConfig]] = None,
        audit_path: Optional[str | Path] = None,
    ):
        self._channels  = channels or []
        self._audit     = Path(audit_path) if audit_path else None

    def route(self, decision: TriageDecision) -> RoutingResult:
        """Route a single triage decision to all applicable channels."""
        payload  = self._build_payload(decision)
        success  = []
        failed   = []
        routed   = []

        for ch in self._channels:
            if not ch.enabled:
                continue
            if decision.priority not in ch.priorities:
                continue
            routed.append(ch.name)
            try:
                ok = ch.handler(decision, payload)
                (success if ok else failed).append(ch.name)
            except Exception as exc:
                failed.append(ch.name)

        result = RoutingResult(
            event_id = decision.event_id,
            priority = decision.priority,
            channels = routed,
            success  = success,
            failed   = failed,
            detail   = (f"Routed to {len(success)}/{len(routed)} channels "
                        f"for {decision.priority}"),
        )
        self._log(result)
        return result

    def route_batch(self, decisions: List[TriageDecision]) -> List[RoutingResult]:
        return [self.route(d) for d in decisions]

    # ── Channel factory helpers ───────────────────────────────────────────────

    @staticmethod
    def make_slack_channel(
        webhook_url: str,
        priorities:  List[str] = None,
    ) -> ChannelConfig:
        """
        Create a Slack channel config using a webhook URL.
        In production, replace the handler body with a real HTTP POST.
        """
        def handler(decision: TriageDecision, payload: str) -> bool:
            # Production: requests.post(webhook_url, json={"text": payload})
            return True   # stub: always succeeds

        return ChannelConfig(
            name      = "slack",
            handler   = handler,
            priorities = priorities or ["P1", "P2"],
        )

    @staticmethod
    def make_pagerduty_channel(
        routing_key: str,
        priorities:  List[str] = None,
    ) -> ChannelConfig:
        """
        Create a PagerDuty channel config.
        Production: POST to https://events.pagerduty.com/v2/enqueue
        """
        def handler(decision: TriageDecision, payload: str) -> bool:
            # Production: requests.post(PD_URL, json={"routing_key": routing_key,
            #   "event_action": "trigger", "payload": {...}})
            return True   # stub

        return ChannelConfig(
            name      = "pagerduty",
            handler   = handler,
            priorities = priorities or ["P1"],
        )

    @staticmethod
    def make_ticket_channel(
        project_key: str,
        priorities:  List[str] = None,
    ) -> ChannelConfig:
        """Create a Jira/ServiceNow ticket channel config stub."""
        def handler(decision: TriageDecision, payload: str) -> bool:
            # Production: create Jira issue or ServiceNow incident
            return True   # stub

        return ChannelConfig(
            name      = "ticket",
            handler   = handler,
            priorities = priorities or ["P2", "P3"],
        )

    @staticmethod
    def make_log_channel(
        log_path: str | Path,
        priorities: List[str] = None,
    ) -> ChannelConfig:
        """Log-to-file channel (always-on fallback)."""
        p = Path(log_path)

        def handler(decision: TriageDecision, payload: str) -> bool:
            import dataclasses
            record = {
                "ts":      datetime.now(timezone.utc).isoformat(),
                "channel": "log",
                **dataclasses.asdict(decision),
            }
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            return True

        return ChannelConfig(
            name      = "log",
            handler   = handler,
            priorities = priorities or ["P1", "P2", "P3", "P4"],
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(decision: TriageDecision) -> str:
        return _DEFAULT_PAYLOAD_TEMPLATE.format(
            priority     = decision.priority,
            event_type   = decision.event_type,
            action       = decision.action,
            matched_rule = decision.matched_rule,
            confidence   = decision.confidence,
            detail       = decision.detail,
        )

    def _log(self, result: RoutingResult) -> None:
        if not self._audit:
            return
        import dataclasses
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **dataclasses.asdict(result),
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
