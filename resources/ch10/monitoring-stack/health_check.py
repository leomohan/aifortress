"""
health_check.py  —  Composable ML endpoint health check framework
AI Fortress · Chapter 10 · Code Sample 10.C

Provides structured health checks for ML model endpoints, feature stores,
and data pipelines. Designed for use as a /health or /readiness endpoint.

Check types:
  ModelLoadCheck      — verifies model is loaded and can produce a prediction
  LatencyCheck        — measures single-inference latency vs a threshold
  PredictionSanity    — verifies output is within an expected range/set
  DependencyCheck     — pings a required upstream service (HTTP or TCP)
  ResourceCheck       — checks CPU/memory headroom via psutil (optional)

Checks are composed into a HealthChecker and evaluated together.
Overall status: OK if all pass, DEGRADED if any warn, UNHEALTHY if any fail.
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ── Check result ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name:     str
    status:   str        # "OK" | "WARN" | "FAIL"
    latency_ms: float    # time taken to run check
    detail:   str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthReport:
    overall:   str              # "OK" | "DEGRADED" | "UNHEALTHY"
    timestamp: str
    service:   str
    checks:    List[CheckResult]
    version:   str = ""

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    def is_healthy(self) -> bool:
        return self.overall == "OK"


# ── Check base class ──────────────────────────────────────────────────────────

class HealthCheck(ABC):
    """Abstract base class for all ML health checks."""

    def __init__(self, name: str, critical: bool = True):
        self.name     = name
        self.critical = critical  # if True, FAIL → UNHEALTHY; else FAIL → DEGRADED

    def run(self) -> CheckResult:
        start = time.monotonic()
        try:
            result = self._execute()
        except Exception as e:
            result = CheckResult(
                name=self.name, status="FAIL",
                latency_ms=0.0, detail=f"Check raised exception: {e}",
            )
        result.latency_ms = round((time.monotonic() - start) * 1000, 2)
        return result

    @abstractmethod
    def _execute(self) -> CheckResult:
        ...


# ── Concrete check types ──────────────────────────────────────────────────────

class ModelLoadCheck(HealthCheck):
    """
    Verifies a model object is loaded and callable.

    Parameters
    ----------
    predict_fn      : Callable that accepts a sample input and returns a prediction.
    sample_input    : Input to pass to predict_fn during check.
    expected_output : Optional expected output for exact match (use for canary).
    """

    def __init__(
        self,
        predict_fn:      Callable,
        sample_input:    Any,
        expected_output: Any = None,
        name:            str = "model_load",
        critical:        bool = True,
    ):
        super().__init__(name, critical)
        self._fn       = predict_fn
        self._input    = sample_input
        self._expected = expected_output

    def _execute(self) -> CheckResult:
        output = self._fn(self._input)
        if self._expected is not None and output != self._expected:
            return CheckResult(
                name=self.name, status="FAIL", latency_ms=0.0,
                detail=f"Unexpected output: expected={self._expected}, got={output}",
                metadata={"expected": str(self._expected), "actual": str(output)},
            )
        return CheckResult(
            name=self.name, status="OK", latency_ms=0.0,
            detail="Model loaded and responding",
            metadata={"sample_output": str(output)[:100]},
        )


class LatencyCheck(HealthCheck):
    """
    Checks that inference latency is within acceptable bounds.

    Parameters
    ----------
    predict_fn      : Callable to benchmark.
    sample_input    : Input for the latency measurement.
    warn_ms         : Warn if latency exceeds this threshold (ms).
    fail_ms         : Fail if latency exceeds this threshold (ms).
    n_warmup        : Number of warmup calls before timing.
    """

    def __init__(
        self,
        predict_fn:   Callable,
        sample_input: Any,
        warn_ms:      float = 200.0,
        fail_ms:      float = 1000.0,
        n_warmup:     int   = 1,
        name:         str   = "inference_latency",
        critical:     bool  = False,
    ):
        super().__init__(name, critical)
        self._fn      = predict_fn
        self._input   = sample_input
        self._warn    = warn_ms
        self._fail    = fail_ms
        self._warmup  = n_warmup

    def _execute(self) -> CheckResult:
        for _ in range(self._warmup):
            self._fn(self._input)
        start  = time.monotonic()
        self._fn(self._input)
        ms     = (time.monotonic() - start) * 1000

        if ms > self._fail:
            status = "FAIL"
        elif ms > self._warn:
            status = "WARN"
        else:
            status = "OK"

        return CheckResult(
            name=self.name, status=status, latency_ms=0.0,
            detail=f"Inference latency: {ms:.1f}ms (warn={self._warn}ms, fail={self._fail}ms)",
            metadata={"latency_ms": round(ms, 2)},
        )


class PredictionSanityCheck(HealthCheck):
    """
    Checks model output is within expected bounds.

    Parameters
    ----------
    predict_fn    : Callable returning a numeric value or list.
    sample_input  : Test input.
    min_val       : Minimum expected output value.
    max_val       : Maximum expected output value.
    """

    def __init__(
        self,
        predict_fn:   Callable,
        sample_input: Any,
        min_val:      float = 0.0,
        max_val:      float = 1.0,
        name:         str   = "prediction_sanity",
        critical:     bool  = True,
    ):
        super().__init__(name, critical)
        self._fn    = predict_fn
        self._input = sample_input
        self._min   = min_val
        self._max   = max_val

    def _execute(self) -> CheckResult:
        output = self._fn(self._input)
        val    = output[0] if hasattr(output, "__len__") else float(output)
        if not (self._min <= val <= self._max):
            return CheckResult(
                name=self.name, status="FAIL", latency_ms=0.0,
                detail=f"Output {val:.4f} outside bounds [{self._min}, {self._max}]",
                metadata={"value": val, "min": self._min, "max": self._max},
            )
        return CheckResult(
            name=self.name, status="OK", latency_ms=0.0,
            detail=f"Output {val:.4f} within bounds [{self._min}, {self._max}]",
            metadata={"value": val},
        )


class DependencyCheck(HealthCheck):
    """
    Checks availability of an upstream dependency (feature store, DB, etc.).

    Parameters
    ----------
    check_fn : Callable → bool. Returns True if dependency is available.
    """

    def __init__(
        self,
        check_fn:  Callable[[], bool],
        name:      str  = "dependency",
        critical:  bool = True,
    ):
        super().__init__(name, critical)
        self._fn = check_fn

    def _execute(self) -> CheckResult:
        ok = self._fn()
        return CheckResult(
            name=self.name,
            status="OK"   if ok else "FAIL",
            latency_ms=0.0,
            detail="Dependency reachable" if ok else "Dependency unreachable",
        )


class ResourceCheck(HealthCheck):
    """
    Checks CPU and memory headroom.

    Parameters
    ----------
    max_cpu_pct : Warn if CPU usage exceeds this % over 1s sample.
    max_mem_pct : Warn if RSS memory usage exceeds this % of system total.
    """

    def __init__(
        self,
        max_cpu_pct: float = 90.0,
        max_mem_pct: float = 90.0,
        name:        str   = "resource_headroom",
        critical:    bool  = False,
    ):
        super().__init__(name, critical)
        self._cpu = max_cpu_pct
        self._mem = max_mem_pct

    def _execute(self) -> CheckResult:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            if cpu > self._cpu or mem > self._mem:
                return CheckResult(
                    name=self.name, status="WARN", latency_ms=0.0,
                    detail=f"CPU={cpu:.1f}% MEM={mem:.1f}% (limits CPU={self._cpu}% MEM={self._mem}%)",
                    metadata={"cpu_pct": cpu, "mem_pct": mem},
                )
            return CheckResult(
                name=self.name, status="OK", latency_ms=0.0,
                detail=f"CPU={cpu:.1f}% MEM={mem:.1f}%",
                metadata={"cpu_pct": cpu, "mem_pct": mem},
            )
        except ImportError:
            return CheckResult(
                name=self.name, status="OK", latency_ms=0.0,
                detail="psutil not installed — resource check skipped",
            )


# ── Health checker ────────────────────────────────────────────────────────────

class HealthChecker:
    """
    Runs a collection of health checks and produces a HealthReport.

    Parameters
    ----------
    service : Service name for the report.
    version : Service version string.
    """

    def __init__(self, service: str = "ml-service", version: str = ""):
        self._checks:  List[HealthCheck] = []
        self._service  = service
        self._version  = version

    def add(self, check: HealthCheck) -> "HealthChecker":
        self._checks.append(check)
        return self

    def run(self) -> HealthReport:
        results = [c.run() for c in self._checks]

        if any(r.status == "FAIL" and self._checks[i].critical
               for i, r in enumerate(results)):
            overall = "UNHEALTHY"
        elif any(r.status in ("FAIL", "WARN") for r in results):
            overall = "DEGRADED"
        else:
            overall = "OK"

        return HealthReport(
            overall   = overall,
            timestamp = datetime.now(timezone.utc).isoformat(),
            service   = self._service,
            checks    = results,
            version   = self._version,
        )
