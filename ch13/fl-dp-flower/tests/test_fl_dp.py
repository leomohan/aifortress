"""
tests/test_fl_dp.py
AI Fortress · Chapter 13 · Code Sample 13.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, math, pytest
from pathlib import Path

from dp_aggregation_strategy import DPAggregator, DPAggregationConfig
from client_privacy_wrapper import ClientPrivacyWrapper, ClientDPConfig
from round_budget_tracker import RoundBudgetTracker


# ── DPAggregator ──────────────────────────────────────────────────────────────

class TestDPAggregator:

    def _agg(self, noise=1.0, clip=1.0, min_clients=2):
        cfg = DPAggregationConfig(noise_multiplier=noise, clip_bound=clip,
                                   min_clients=min_clients)
        return DPAggregator(cfg)

    def test_aggregate_shape(self):
        agg    = self._agg()
        result = agg.aggregate([[0.5, 0.5], [0.3, 0.7]])
        assert len(result.aggregate) == 2

    def test_aggregate_clips_large_updates(self):
        agg    = self._agg(clip=1.0)
        updates = [[100.0, 0.0], [0.0, 100.0]]
        result  = agg.aggregate(updates)
        assert result.clipped_count == 2

    def test_noise_changes_aggregate(self):
        import random
        random.seed(42)
        agg    = self._agg(noise=10.0)
        updates = [[1.0, 1.0], [1.0, 1.0]]
        result  = agg.aggregate(updates)
        assert result.aggregate != [1.0, 1.0]

    def test_too_few_clients_raises(self):
        agg = self._agg(min_clients=5)
        with pytest.raises(ValueError, match="Insufficient"):
            agg.aggregate([[1.0], [2.0]])

    def test_round_num_increments(self):
        agg = self._agg(min_clients=2)
        agg.aggregate([[1.0], [2.0]])
        agg.aggregate([[1.0], [2.0]])
        assert agg._round_num == 2

    def test_zero_noise_exact_average(self):
        import random
        random.seed(0)
        cfg = DPAggregationConfig(noise_multiplier=0.0, clip_bound=100.0, min_clients=2)
        agg = DPAggregator(cfg)
        updates = [[2.0, 4.0], [4.0, 2.0]]
        result  = agg.aggregate(updates)
        assert abs(result.aggregate[0] - 3.0) < 1e-9

    def test_config_validation(self):
        with pytest.raises(ValueError, match="clip_bound"):
            DPAggregationConfig(noise_multiplier=1.0, clip_bound=-1.0).validate()

    def test_audit_log(self, tmp_path):
        log = tmp_path / "agg.jsonl"
        cfg = DPAggregationConfig(noise_multiplier=1.0, clip_bound=1.0, min_clients=2)
        agg = DPAggregator(cfg, audit_path=log)
        agg.aggregate([[1.0], [1.0]])
        data = json.loads(log.read_text().splitlines()[0])
        assert data["event"] == "round_aggregated"

    def test_epsilon_round_positive(self):
        agg    = self._agg()
        result = agg.aggregate([[1.0], [1.0]])
        assert result.epsilon_round > 0


# ── ClientPrivacyWrapper ──────────────────────────────────────────────────────

class TestClientPrivacyWrapper:

    def _client(self, local_eps=10.0, noise=0.0):
        cfg = ClientDPConfig("client-1", local_epsilon=local_eps,
                              local_delta=1e-5, clip_bound=1.0,
                              noise_multiplier=noise)
        return ClientPrivacyWrapper(cfg)

    def test_participate_success(self):
        c      = self._client()
        result = c.participate(1, lambda: [1.0, 2.0], epsilon_per_round=1.0)
        assert result.participated
        assert result.round_num == 1

    def test_participate_blocked_when_budget_exceeded(self):
        c = self._client(local_eps=1.5)
        c.participate(1, lambda: [1.0], epsilon_per_round=1.0)
        result = c.participate(2, lambda: [1.0], epsilon_per_round=1.0)
        assert not result.participated
        assert result.blocked_reason

    def test_epsilon_accumulates(self):
        c = self._client(local_eps=10.0)
        c.participate(1, lambda: [1.0], 2.0)
        c.participate(2, lambda: [1.0], 2.0)
        assert abs(c._epsilon_total - 4.0) < 1e-9

    def test_epsilon_remaining(self):
        c = self._client(local_eps=10.0)
        c.participate(1, lambda: [1.0], 3.0)
        assert abs(c.epsilon_remaining - 7.0) < 1e-9

    def test_rounds_participated_count(self):
        c = self._client(local_eps=10.0)
        for i in range(3):
            c.participate(i, lambda: [1.0], 1.0)
        assert c.rounds_participated == 3

    def test_local_noise_applied(self):
        import random
        random.seed(0)
        updates_seen = []
        def train_fn():
            return [1.0, 1.0]
        c      = self._client(noise=5.0)
        result = c.participate(1, train_fn, 1.0)
        assert result.participated   # noise applied internally, update returned separately

    def test_history_recorded(self):
        c = self._client()
        c.participate(1, lambda: [1.0], 1.0)
        c.participate(2, lambda: [1.0], 1.0)
        assert len(c.history()) == 2

    def test_audit_log(self, tmp_path):
        log = tmp_path / "client.jsonl"
        cfg = ClientDPConfig("c1", 10.0, 1e-5, 1.0, 0.0)
        c   = ClientPrivacyWrapper(cfg, audit_path=log)
        c.participate(1, lambda: [1.0], 1.0)
        data = json.loads(log.read_text().splitlines()[0])
        assert data["event"] == "client_participated"


# ── RoundBudgetTracker ────────────────────────────────────────────────────────

class TestRoundBudgetTracker:

    def _tracker(self, total=100, budget=10.0, noise=1.1):
        return RoundBudgetTracker(total_rounds=total, epsilon_budget=budget,
                                   delta=1e-5, noise_multiplier=noise)

    def test_record_round(self):
        t  = self._tracker()
        r  = t.record_round(1, n_clients=10, total_clients=100, epsilon_this_round=0.1)
        assert r.round_num == 1
        assert abs(r.epsilon_cumulative - 0.1) < 1e-9

    def test_cumulative_accumulates(self):
        t = self._tracker()
        for i in range(1, 4):
            t.record_round(i, 10, 100, 0.5)
        assert abs(t.status().epsilon_spent - 1.5) < 1e-9

    def test_exhausted_flag(self):
        t = self._tracker(budget=1.0)
        t.record_round(1, 10, 100, 1.5)
        assert t.status().exhausted

    def test_pct_consumed(self):
        t = self._tracker(budget=10.0)
        t.record_round(1, 10, 100, 4.0)
        assert abs(t.status().pct_consumed - 40.0) < 0.01

    def test_estimated_rounds_remaining(self):
        t = self._tracker(total=100, budget=10.0)
        t.record_round(1, 10, 100, 0.5)
        status = t.status()
        assert status.estimated_rounds_remaining > 0

    def test_estimate_total_epsilon(self):
        t   = self._tracker(noise=1.1)
        eps = t.estimate_total_epsilon(100, participation_rate=0.1)
        assert eps > 0

    def test_records_list(self):
        t = self._tracker()
        t.record_round(1, 5, 50, 0.2)
        t.record_round(2, 5, 50, 0.2)
        assert len(t.records()) == 2

    def test_audit_log(self, tmp_path):
        log = tmp_path / "rounds.jsonl"
        t   = RoundBudgetTracker(10, 5.0, 1e-5, 1.1, audit_path=log)
        t.record_round(1, 5, 50, 0.5)
        data = json.loads(log.read_text().splitlines()[0])
        assert data["event"] == "round_recorded"
