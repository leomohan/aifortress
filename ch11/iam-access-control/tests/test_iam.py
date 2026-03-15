"""
tests/test_iam.py
AI Fortress · Chapter 11 · Code Sample 11.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from rbac_engine import RBACEngine, ALL_PERMISSIONS
from abac_policy_evaluator import ABACPolicyEvaluator, ABACRequest, ABACPolicy
from permission_graph import PermissionGraph
from time_bound_access import TimeBoundAccessManager


# ── RBACEngine ────────────────────────────────────────────────────────────────

class TestRBACEngine:

    def test_assign_and_check_permission(self):
        engine = RBACEngine()
        engine.assign_role("alice", "data-scientist", granted_by="admin")
        dec = engine.check("alice", "training:run")
        assert dec.allowed
        assert "data-scientist" in dec.roles

    def test_unknown_role_raises(self):
        engine = RBACEngine()
        with pytest.raises(ValueError):
            engine.assign_role("alice", "superuser", granted_by="admin")

    def test_permission_not_granted(self):
        engine = RBACEngine()
        engine.assign_role("alice", "auditor", granted_by="admin")
        dec = engine.check("alice", "model:deploy")
        assert not dec.allowed

    def test_mlops_admin_has_all_permissions(self):
        engine = RBACEngine()
        engine.assign_role("root", "mlops-admin", granted_by="system")
        perms = engine.get_effective_permissions("root")
        assert ALL_PERMISSIONS.issubset(perms)

    def test_role_inheritance_data_scientist_includes_model_reviewer(self):
        engine = RBACEngine()
        engine.assign_role("bob", "data-scientist", granted_by="admin")
        dec = engine.check("bob", "model:read")
        assert dec.allowed

    def test_ml_engineer_inherits_data_scientist(self):
        engine = RBACEngine()
        engine.assign_role("carol", "ml-engineer", granted_by="admin")
        perms = engine.get_effective_permissions("carol")
        assert "pipeline:execute" in perms
        assert "training:run"     in perms

    def test_revoke_removes_permission(self):
        engine = RBACEngine()
        engine.assign_role("dave", "data-scientist", granted_by="admin")
        engine.revoke_role("dave", "data-scientist", revoked_by="admin")
        dec = engine.check("dave", "training:run")
        assert not dec.allowed

    def test_expired_assignment_not_active(self):
        engine  = RBACEngine()
        past    = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        engine.assign_role("eve", "ml-engineer", granted_by="admin", expires_at=past)
        active  = engine.get_active_assignments("eve")
        assert len(active) == 0

    def test_future_expiry_is_active(self):
        engine  = RBACEngine()
        future  = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        engine.assign_role("frank", "ml-engineer", granted_by="admin", expires_at=future)
        active  = engine.get_active_assignments("frank")
        assert len(active) == 1

    def test_list_principals_with_permission(self):
        engine = RBACEngine()
        engine.assign_role("alice", "data-scientist", granted_by="admin")
        engine.assign_role("bob",   "auditor",        granted_by="admin")
        principals = engine.list_principals_with_permission("training:run")
        assert "alice" in principals
        assert "bob"   not in principals

    def test_custom_role(self):
        engine = RBACEngine(custom_roles={"custom-reviewer": {"model:read", "audit:read"}})
        engine.assign_role("grace", "custom-reviewer", granted_by="admin")
        assert engine.check("grace", "model:read").allowed
        assert not engine.check("grace", "model:write").allowed

    def test_audit_log_written(self, tmp_path):
        log    = tmp_path / "iam_audit.jsonl"
        engine = RBACEngine(audit_path=log)
        engine.assign_role("alice", "auditor", granted_by="admin")
        engine.check("alice", "audit:read")
        lines  = log.read_text().splitlines()
        events = [json.loads(l)["event"] for l in lines]
        assert "role_assigned" in events
        assert "access_check"  in events

    def test_multiple_roles_combined_permissions(self):
        engine = RBACEngine()
        engine.assign_role("harry", "auditor",      granted_by="admin")
        engine.assign_role("harry", "model-reviewer", granted_by="admin")
        perms = engine.get_effective_permissions("harry")
        assert "audit:read"  in perms
        assert "model:read"  in perms


# ── ABACPolicyEvaluator ───────────────────────────────────────────────────────

SAMPLE_POLICIES = [
    {
        "id":          "deny-prod-no-mfa",
        "effect":      "deny",
        "conditions":  {"resource.environment": "production", "context.mfa": {"ne": True}},
        "description": "Block production access without MFA",
    },
    {
        "id":          "allow-own-model",
        "effect":      "allow",
        "conditions":  {
            "resource.type": "model",
            "resource.owner": {"eq_subject": "sub.user_id"},
        },
        "description": "Allow users to access their own models",
    },
    {
        "id":          "allow-nlp-team-training",
        "effect":      "allow",
        "conditions":  {"sub.team": "nlp", "resource.type": "training-job"},
        "description": "NLP team can access training jobs",
    },
    {
        "id":          "allow-senior-deploy",
        "effect":      "allow",
        "conditions":  {"sub.clearance": {"gte": 3}, "resource.type": "model"},
        "description": "Clearance level 3+ can deploy models",
    },
]


class TestABACPolicyEvaluator:

    def _eval(self, policies=None):
        return ABACPolicyEvaluator.from_list(policies or SAMPLE_POLICIES)

    def test_deny_prod_without_mfa(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "alice"},
            resource = {"type": "model", "environment": "production"},
            context  = {"mfa": False},
            action   = "model:deploy",
        )
        dec = ev.evaluate(req)
        assert not dec.allowed
        assert dec.matched_policy == "deny-prod-no-mfa"

    def test_allow_with_mfa(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "alice", "clearance": 3},
            resource = {"type": "model", "environment": "production"},
            context  = {"mfa": True},
            action   = "model:deploy",
        )
        dec = ev.evaluate(req)
        assert dec.allowed

    def test_allow_own_model(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "alice"},
            resource = {"type": "model", "owner": "alice", "environment": "staging"},
            context  = {"mfa": True},
            action   = "model:read",
        )
        dec = ev.evaluate(req)
        assert dec.allowed
        assert dec.matched_policy == "allow-own-model"

    def test_deny_other_user_model(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "mallory"},
            resource = {"type": "model", "owner": "alice", "environment": "staging"},
            context  = {"mfa": True},
            action   = "model:read",
        )
        dec = ev.evaluate(req)
        assert not dec.allowed

    def test_team_policy(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "bob", "team": "nlp"},
            resource = {"type": "training-job"},
            context  = {},
            action   = "training:run",
        )
        dec = ev.evaluate(req)
        assert dec.allowed

    def test_clearance_gte(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "carol", "clearance": 4},
            resource = {"type": "model"},
            context  = {"mfa": True},
            action   = "model:deploy",
        )
        dec = ev.evaluate(req)
        assert dec.allowed

    def test_clearance_below_threshold_denied(self):
        ev  = self._eval()
        req = ABACRequest(
            subject  = {"user_id": "dave", "clearance": 1},
            resource = {"type": "model"},
            context  = {"mfa": True},
            action   = "model:deploy",
        )
        dec = ev.evaluate(req)
        assert not dec.allowed

    def test_default_deny_no_matching_policy(self):
        ev  = ABACPolicyEvaluator()   # no policies
        req = ABACRequest(
            subject={"user_id": "x"}, resource={}, context={}, action="anything"
        )
        dec = ev.evaluate(req)
        assert not dec.allowed
        assert dec.matched_policy == "default-deny"

    def test_deny_overrides_allow(self):
        policies = [
            {"id": "deny-all",  "effect": "deny",  "conditions": {"sub.user_id": "mallory"}},
            {"id": "allow-all", "effect": "allow", "conditions": {}},
        ]
        ev  = ABACPolicyEvaluator.from_list(policies)
        req = ABACRequest(
            subject={"user_id": "mallory"}, resource={}, context={}, action="*"
        )
        dec = ev.evaluate(req)
        assert not dec.allowed
        assert dec.matched_policy == "deny-all"

    def test_add_policy_dynamic(self):
        ev = ABACPolicyEvaluator()
        ev.add_policy(ABACPolicy(
            id="custom-allow", effect="allow",
            conditions={"sub.user_id": "frank"},
        ))
        req = ABACRequest(
            subject={"user_id": "frank"}, resource={}, context={}, action="test"
        )
        assert ev.evaluate(req).allowed

    def test_audit_log(self, tmp_path):
        log = tmp_path / "abac.jsonl"
        ev  = ABACPolicyEvaluator.from_list(SAMPLE_POLICIES, audit_path=log)
        req = ABACRequest(
            subject={"user_id": "alice"}, resource={"type": "model", "owner": "alice",
            "environment": "staging"}, context={"mfa": True}, action="model:read"
        )
        ev.evaluate(req)
        lines = log.read_text().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert "allowed"  in record
        assert "policy"   in record


# ── PermissionGraph ───────────────────────────────────────────────────────────

class TestPermissionGraph:

    def _graph(self):
        g = PermissionGraph()
        g.add_role("viewer",    {"read"},             parents=[])
        g.add_role("editor",    {"write"},            parents=["viewer"])
        g.add_role("admin",     {"delete", "manage"}, parents=["editor"])
        g.add_role("superadmin",{"nuke"},             parents=["admin"])
        return g

    def test_effective_permissions_includes_inherited(self):
        g = self._graph()
        perms = g.effective_permissions("admin")
        assert "read"   in perms
        assert "write"  in perms
        assert "delete" in perms

    def test_effective_permissions_leaf_role(self):
        g     = self._graph()
        perms = g.effective_permissions("viewer")
        assert perms == frozenset({"read"})

    def test_no_cycle_detected(self):
        g      = self._graph()
        report = g.detect_cycles()
        assert not report.has_cycle

    def test_cycle_detected(self):
        g = PermissionGraph()
        g.add_role("a", {"perm_a"}, parents=["b"])
        g.add_role("b", {"perm_b"}, parents=["a"])   # cycle: a → b → a
        report = g.detect_cycles()
        assert report.has_cycle

    def test_blast_radius(self):
        g  = self._graph()
        br = g.blast_radius("read")
        assert "viewer"     in br
        assert "editor"     in br
        assert "admin"      in br
        assert "superadmin" in br

    def test_blast_radius_restricted_permission(self):
        g  = self._graph()
        br = g.blast_radius("nuke")
        assert br == ["superadmin"]

    def test_compare_roles(self):
        g   = self._graph()
        cmp = g.compare_roles("admin", "viewer")
        assert "write"  in cmp["admin_only"]
        assert "delete" in cmp["admin_only"]
        assert "read"   in cmp["shared"]

    def test_shortest_path_to_permission(self):
        g    = self._graph()
        path = g.shortest_path_to_permission("superadmin", "read")
        assert path is not None
        assert path[0] == "superadmin"
        assert "viewer" in path

    def test_permission_not_reachable_returns_none(self):
        g    = self._graph()
        path = g.shortest_path_to_permission("viewer", "nuke")
        assert path is None

    def test_analyse_runs_without_error(self):
        g      = self._graph()
        result = g.analyse()
        assert len(result.roles) == 4
        assert not result.cycles.has_cycle
        assert "read" in result.blast_radius

    def test_from_rbac_engine(self):
        engine = RBACEngine()
        g      = PermissionGraph.from_rbac_engine(engine)
        perms  = g.effective_permissions("mlops-admin")
        assert "model:deploy" in perms


# ── TimeBoundAccessManager ────────────────────────────────────────────────────

class TestTimeBoundAccessManager:

    def test_grant_and_check_valid(self):
        mgr   = TimeBoundAccessManager()
        grant = mgr.grant("alice", "model:deploy", "admin", ttl_seconds=3600)
        result = mgr.check("alice", "model:deploy")
        assert result.valid
        assert result.grant_id == grant.grant_id

    def test_expired_grant_invalid(self):
        mgr = TimeBoundAccessManager()
        mgr.grant("alice", "model:deploy", "admin", ttl_seconds=10)
        future_now = datetime.now(timezone.utc) + timedelta(seconds=20)
        result     = mgr.check("alice", "model:deploy", now=future_now)
        assert not result.valid

    def test_revoked_grant_invalid(self):
        mgr   = TimeBoundAccessManager()
        grant = mgr.grant("bob", "data:read", "admin", ttl_seconds=3600)
        mgr.revoke(grant.grant_id, revoked_by="admin")
        result = mgr.check("bob", "data:read")
        assert not result.valid

    def test_wrong_permission_no_match(self):
        mgr = TimeBoundAccessManager()
        mgr.grant("carol", "model:read", "admin", ttl_seconds=3600)
        result = mgr.check("carol", "model:deploy")
        assert not result.valid

    def test_resource_scoped_grant(self):
        mgr = TimeBoundAccessManager()
        mgr.grant("dave", "model:deploy", "admin", ttl_seconds=3600,
                  resource="fraud-model-v2")
        result_right  = mgr.check("dave", "model:deploy", resource="fraud-model-v2")
        result_wrong  = mgr.check("dave", "model:deploy", resource="other-model")
        assert result_right.valid
        assert not result_wrong.valid

    def test_near_expiry_alerts(self):
        mgr = TimeBoundAccessManager(warn_minutes=30)
        mgr.grant("eve", "pipeline:execute", "admin", ttl_seconds=600)  # 10 min
        alerts = mgr.near_expiry_alerts()
        assert len(alerts) == 1
        assert alerts[0].severity in ("CRITICAL", "WARNING")

    def test_no_near_expiry_if_far_future(self):
        mgr = TimeBoundAccessManager(warn_minutes=30)
        mgr.grant("frank", "data:read", "admin", ttl_seconds=7200)  # 2 hours
        alerts = mgr.near_expiry_alerts()
        assert len(alerts) == 0

    def test_cleanup_removes_expired(self):
        mgr = TimeBoundAccessManager()
        mgr.grant("grace", "model:read", "admin", ttl_seconds=1)
        future_now = datetime.now(timezone.utc) + timedelta(seconds=10)
        removed    = mgr.cleanup_expired(now=future_now)
        assert removed == 1
        result     = mgr.check("grace", "model:read")
        assert not result.valid

    def test_active_grants_list(self):
        mgr = TimeBoundAccessManager()
        mgr.grant("harry", "model:read",   "admin", ttl_seconds=3600)
        mgr.grant("harry", "model:deploy", "admin", ttl_seconds=3600)
        active = mgr.active_grants()
        assert len(active) == 2

    def test_audit_log_events(self, tmp_path):
        log = tmp_path / "tb_audit.jsonl"
        mgr = TimeBoundAccessManager(audit_path=log)
        g   = mgr.grant("alice", "model:deploy", "admin", ttl_seconds=3600)
        mgr.check("alice", "model:deploy")
        mgr.revoke(g.grant_id, revoked_by="admin")
        lines  = log.read_text().splitlines()
        events = {json.loads(l)["event"] for l in lines}
        assert "grant_created" in events
        assert "grant_used"    in events
        assert "grant_revoked" in events

    def test_revoke_returns_false_for_missing_grant(self):
        mgr = TimeBoundAccessManager()
        assert not mgr.revoke("nonexistent-id")
