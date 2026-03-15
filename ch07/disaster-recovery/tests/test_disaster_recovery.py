"""
tests/test_disaster_recovery.py
AI Fortress · Chapter 7 · Code Sample 7.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from backup_scheduler import (
    BackupScheduler, BackupSchedule, BackupJob, standard_ml_schedules
)
from rpo_tracker import RPOTracker
from restoration_verifier import RestorationVerifier
from runbook_generator import RunbookGenerator, EscalationContact


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_schedule(sid="sched-1", rpo=3600, tier=1) -> BackupSchedule:
    return BackupSchedule(
        schedule_id   = sid,
        name          = f"Schedule {sid}",
        resource_id   = "ml-models-bucket",
        resource_type = "s3_bucket",
        tier          = tier,
        rpo_seconds   = rpo,
        description   = "Test schedule",
        destination   = "arn:aws:backup:us-east-1:123:vault/ml-vault",
    )


def _make_job(schedule_id: str, offset_seconds: int = 0, status: str = "success") -> BackupJob:
    """Return a job completed `offset_seconds` ago."""
    completed = (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()
    return BackupJob(
        job_id       = str(uuid.uuid4()),
        schedule_id  = schedule_id,
        started_at   = completed,
        completed_at = completed,
        status       = status,
        size_bytes   = 1024,
        checksum     = "abc123",
    )


# ── BackupScheduler ───────────────────────────────────────────────────────────

class TestBackupScheduler:

    def test_register_and_retrieve(self):
        sched = BackupScheduler()
        s     = _make_schedule()
        sched.register(s)
        assert sched.get_schedule(s.schedule_id) is s

    def test_all_schedules(self):
        sched = BackupScheduler()
        sched.register(_make_schedule("s1"))
        sched.register(_make_schedule("s2"))
        assert len(sched.all_schedules()) == 2

    def test_last_successful_job_none_when_empty(self):
        sched = BackupScheduler()
        sched.register(_make_schedule("s1"))
        assert sched.last_successful_job("s1") is None

    def test_last_successful_job_picks_latest(self):
        sched = BackupScheduler()
        sched.register(_make_schedule("s1"))
        j1 = _make_job("s1", offset_seconds=7200)
        j2 = _make_job("s1", offset_seconds=100)
        sched.record_job(j1)
        sched.record_job(j2)
        last = sched.last_successful_job("s1")
        assert last.job_id == j2.job_id

    def test_failed_jobs_ignored(self):
        sched = BackupScheduler()
        sched.register(_make_schedule("s1"))
        sched.record_job(_make_job("s1", status="failed"))
        assert sched.last_successful_job("s1") is None

    def test_no_overdue_when_recent_backup(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        sched.record_job(_make_job(s.schedule_id, offset_seconds=100))
        alerts = sched.check_overdue()
        assert len(alerts) == 0

    def test_overdue_alert_when_rpo_breached(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        sched.record_job(_make_job(s.schedule_id, offset_seconds=7300))  # > 1h
        alerts = sched.check_overdue()
        assert len(alerts) == 1
        assert alerts[0].severity in ("WARNING", "CRITICAL")

    def test_critical_alert_when_2x_rpo_exceeded(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        sched.record_job(_make_job(s.schedule_id, offset_seconds=3600 * 3))  # 3× RPO
        alerts = sched.check_overdue()
        assert any(a.severity == "CRITICAL" for a in alerts)

    def test_save_and_load_state(self, tmp_path):
        sched = BackupScheduler()
        s     = _make_schedule()
        sched.register(s)
        sched.record_job(_make_job(s.schedule_id))
        path  = tmp_path / "state.json"
        sched.save_state(path)
        loaded = BackupScheduler.load_state(path)
        assert loaded.get_schedule(s.schedule_id) is not None
        assert len(loaded.job_history(s.schedule_id)) == 1

    def test_standard_ml_schedules_factory(self):
        schedules = standard_ml_schedules(
            "ml-checkpoints", "ml-datasets", "ml-metadata", "arn:aws:backup:::vault/v"
        )
        assert len(schedules) == 3
        tiers = {s.tier for s in schedules}
        assert tiers == {1, 2, 3}


# ── RPOTracker ────────────────────────────────────────────────────────────────

class TestRPOTracker:

    def test_compliant_when_recent_backup(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        sched.record_job(_make_job(s.schedule_id, offset_seconds=100))
        tracker = RPOTracker(sched)
        report  = tracker.report()
        assert report.compliant == 1
        assert report.overall_pass

    def test_breach_when_no_backup(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        tracker = RPOTracker(sched)
        report  = tracker.report()
        assert report.breach == 1
        assert not report.overall_pass

    def test_warning_zone(self):
        sched = BackupScheduler()
        s     = _make_schedule(rpo=3600)
        sched.register(s)
        # 85% of RPO consumed — warning
        sched.record_job(_make_job(s.schedule_id, offset_seconds=int(3600 * 0.85)))
        tracker = RPOTracker(sched)
        report  = tracker.report()
        assert report.warning == 1

    def test_report_save_json(self, tmp_path):
        sched = BackupScheduler()
        sched.register(_make_schedule())
        tracker = RPOTracker(sched)
        report  = tracker.report()
        path    = tmp_path / "rpo.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "overall_pass" in data

    def test_summary_string(self):
        sched = BackupScheduler()
        sched.register(_make_schedule())
        tracker = RPOTracker(sched)
        report  = tracker.report()
        assert "RPO Compliance" in report.summary()


# ── RestorationVerifier ───────────────────────────────────────────────────────

class TestRestorationVerifier:

    def _make_file(self, tmp_path: Path, content: bytes) -> Path:
        p = tmp_path / f"artefact_{uuid.uuid4().hex[:8]}.bin"
        p.write_bytes(content)
        return p

    def test_valid_restoration_passes(self, tmp_path):
        content = os.urandom(1024)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier(operator_id="ops")
        cert    = rv.verify(p, sha256, len(content), resource_id="ml-models")
        assert cert.overall_pass
        assert cert.sha256_verified
        assert cert.size_verified

    def test_tampered_file_fails(self, tmp_path):
        content = os.urandom(1024)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        # Tamper
        p.write_bytes(os.urandom(1024))
        rv   = RestorationVerifier()
        cert = rv.verify(p, sha256, 1024)
        assert not cert.sha256_verified
        assert not cert.overall_pass

    def test_wrong_size_fails(self, tmp_path):
        content = os.urandom(512)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier()
        cert    = rv.verify(p, sha256, 1024)   # wrong expected size
        assert not cert.size_verified
        assert not cert.overall_pass

    def test_smoke_test_failure_fails(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier()
        cert    = rv.verify(p, sha256, len(content), smoke_test_fn=lambda _: False)
        assert cert.smoke_test_passed is False
        assert not cert.overall_pass

    def test_smoke_test_pass_included(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier()
        cert    = rv.verify(p, sha256, len(content), smoke_test_fn=lambda _: True)
        assert cert.smoke_test_passed is True
        assert cert.overall_pass

    def test_certificate_saved_and_loaded(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier()
        cert    = rv.verify(p, sha256, len(content))
        cert_path = tmp_path / "cert.json"
        cert.save(cert_path)
        from restoration_verifier import RestorationCertificate
        loaded = RestorationCertificate.load(cert_path)
        assert loaded.cert_id == cert.cert_id
        assert loaded.overall_pass == cert.overall_pass

    def test_sha256_proof_tamper_evident(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_file(tmp_path, content)
        sha256  = hashlib.sha256(content).hexdigest()
        rv      = RestorationVerifier()
        cert    = rv.verify(p, sha256, len(content))
        assert len(cert.sha256_proof) == 64


# ── RunbookGenerator ──────────────────────────────────────────────────────────

class TestRunbookGenerator:

    def _make_contacts(self):
        return [
            EscalationContact("Alice", "ML Lead", "alice@example.com", "+1-555-0100"),
            EscalationContact("Bob",   "Infra",   "bob@example.com"),
        ]

    def test_generate_returns_runbook(self):
        schedules = standard_ml_schedules(
            "ml-checkpoints", "ml-datasets", "ml-metadata", "arn:backup:::vault"
        )
        gen  = RunbookGenerator()
        rb   = gen.generate("ML Prod", schedules, self._make_contacts())
        assert rb.platform == "ML Prod"
        assert len(rb.schedules) == 3
        assert len(rb.procedures) >= 5
        assert len(rb.tabletop)   >= 5

    def test_save_json(self, tmp_path):
        schedules = standard_ml_schedules("b1", "b2", "t1", "vault")
        gen = RunbookGenerator()
        rb  = gen.generate("ML Prod", schedules, self._make_contacts())
        path = tmp_path / "runbook.json"
        rb.save_json(path)
        data = json.loads(path.read_text())
        assert "platform" in data
        assert "procedures" in data

    def test_save_markdown(self, tmp_path):
        schedules = standard_ml_schedules("b1", "b2", "t1", "vault")
        gen = RunbookGenerator()
        rb  = gen.generate("ML Prod", schedules, self._make_contacts())
        path = tmp_path / "runbook.md"
        rb.save_markdown(path)
        md = path.read_text()
        assert "Disaster Recovery Runbook" in md
        assert "RTO" in md
        assert "Tabletop" in md

    def test_rpo_in_report(self):
        schedules = standard_ml_schedules("b1", "b2", "t1", "vault")
        gen = RunbookGenerator()
        rb  = gen.generate("ML Prod", schedules, self._make_contacts())
        assert all(v > 0 for v in rb.rpo_seconds.values())
        assert all(v > 0 for v in rb.rto_seconds.values())
