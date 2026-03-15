"""
ip_policy_enforcer.py  —  CIDR-based IP allowlist/denylist for ML APIs
AI Fortress · Chapter 9 · Code Sample 9.A

Enforces IP-based access controls on ML API endpoints:
  - Per-endpoint allowlists (CIDR ranges that may access that endpoint)
  - Global denylist (blocked CIDRs regardless of endpoint)
  - Default-deny mode: reject any IP not in an allowlist
  - Default-allow mode: allow any IP not in the denylist
  - Structured deny log for SIEM integration

Uses only stdlib `ipaddress` — no external dependencies.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union


IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class IPDecision:
    allowed:    bool
    client_ip:  str
    endpoint:   str
    reason:     str          # "allowlist_match" | "denylist_match" | "default_deny" | "default_allow"
    matched_cidr: str = ""


def _parse_network(cidr: str) -> IPNetwork:
    return ipaddress.ip_network(cidr, strict=False)


def _parse_address(ip: str) -> IPAddress:
    return ipaddress.ip_address(ip)


def _in_networks(ip: IPAddress, networks: List[IPNetwork]) -> Optional[str]:
    """Return the first matching CIDR string, or None."""
    for net in networks:
        if ip in net:
            return str(net)
    return None


class IPPolicyEnforcer:
    """
    Enforces IP-based access policies for ML API endpoints.

    Parameters
    ----------
    global_denylist  : CIDRs always denied regardless of endpoint.
    default_deny     : If True, IPs not in any allowlist are denied.
                       If False (default-allow), IPs not in denylist are allowed.
    audit_path       : Optional path to write JSON Lines deny log.
    """

    def __init__(
        self,
        global_denylist: Optional[List[str]] = None,
        default_deny:    bool = False,
        audit_path:      Optional[str | Path] = None,
    ):
        self._deny_nets:     List[IPNetwork]              = []
        self._allow_nets:    Dict[str, List[IPNetwork]]   = {}   # endpoint → list
        self._default_deny   = default_deny
        self._audit          = Path(audit_path) if audit_path else None

        for cidr in (global_denylist or []):
            self._deny_nets.append(_parse_network(cidr))

    def add_allowlist(self, endpoint: str, cidrs: List[str]) -> None:
        """Register allowed CIDRs for a specific endpoint pattern."""
        self._allow_nets.setdefault(endpoint, [])
        for cidr in cidrs:
            self._allow_nets[endpoint].append(_parse_network(cidr))

    def add_denylist(self, cidrs: List[str]) -> None:
        """Add CIDRs to the global denylist."""
        for cidr in cidrs:
            self._deny_nets.append(_parse_network(cidr))

    def evaluate(self, client_ip: str, endpoint: str = "*") -> IPDecision:
        """
        Evaluate whether `client_ip` may access `endpoint`.

        Parameters
        ----------
        client_ip : Client IP address (IPv4 or IPv6 string)
        endpoint  : Request path (used to look up per-endpoint allowlists)
        """
        try:
            ip = _parse_address(client_ip)
        except ValueError:
            decision = IPDecision(
                allowed=False, client_ip=client_ip, endpoint=endpoint,
                reason="invalid_ip", matched_cidr="",
            )
            self._log(decision)
            return decision

        # 1. Global denylist check (always applied first)
        matched = _in_networks(ip, self._deny_nets)
        if matched:
            decision = IPDecision(
                allowed=False, client_ip=client_ip, endpoint=endpoint,
                reason="denylist_match", matched_cidr=matched,
            )
            self._log(decision)
            return decision

        # 2. Per-endpoint allowlist check
        endpoint_nets = self._allow_nets.get(endpoint, self._allow_nets.get("*", []))
        if endpoint_nets:
            matched = _in_networks(ip, endpoint_nets)
            if matched:
                return IPDecision(
                    allowed=True, client_ip=client_ip, endpoint=endpoint,
                    reason="allowlist_match", matched_cidr=matched,
                )
            # IP not in allowlist for this endpoint
            decision = IPDecision(
                allowed=False, client_ip=client_ip, endpoint=endpoint,
                reason="not_in_allowlist", matched_cidr="",
            )
            self._log(decision)
            return decision

        # 3. Default policy
        if self._default_deny:
            decision = IPDecision(
                allowed=False, client_ip=client_ip, endpoint=endpoint,
                reason="default_deny",
            )
            self._log(decision)
            return decision

        return IPDecision(
            allowed=True, client_ip=client_ip, endpoint=endpoint,
            reason="default_allow",
        )

    def _log(self, decision: IPDecision) -> None:
        if self._audit is None:
            return
        record = {
            "ts":          datetime.now(timezone.utc).isoformat(),
            "allowed":     decision.allowed,
            "client_ip":   decision.client_ip,
            "endpoint":    decision.endpoint,
            "reason":      decision.reason,
            "matched_cidr": decision.matched_cidr,
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
