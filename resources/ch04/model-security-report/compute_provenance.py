"""
compute_provenance.py  —  Compute environment and isolation evidence
AI Fortress · Chapter 4 · Code Sample 4.C
"""
from __future__ import annotations
import platform, socket, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ComputeProvenance:
    job_id:           str
    started_at:       str
    completed_at:     str = ""
    hostname:         str = ""
    os_platform:      str = ""
    cpu_count:        Optional[int] = None
    gpu_count:        Optional[int] = None
    gpu_model:        str = ""
    cloud_provider:   str = ""     # "aws" | "gcp" | "azure" | "on-prem"
    cloud_region:     str = ""
    instance_type:    str = ""
    account_id:       str = ""
    network_isolated: bool = False
    gpu_hygiene_cert: str = ""     # path/ref to GPU hygiene certificate
    workspace_wiped:  bool = False

    @classmethod
    def capture(cls, job_id: Optional[str] = None) -> "ComputeProvenance":
        """Capture current compute environment."""
        gpu_count, gpu_model = cls._gpu_info()
        return cls(
            job_id      = job_id or str(uuid.uuid4()),
            started_at  = datetime.now(timezone.utc).isoformat(),
            hostname    = socket.gethostname(),
            os_platform = f"{platform.system()} {platform.release()} {platform.machine()}",
            cpu_count   = _safe_cpu_count(),
            gpu_count   = gpu_count,
            gpu_model   = gpu_model,
        )

    def complete(self) -> None:
        self.completed_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _gpu_info():
        try:
            import torch
            if torch.cuda.is_available():
                n = torch.cuda.device_count()
                model = torch.cuda.get_device_name(0) if n > 0 else ""
                return n, model
        except ImportError:
            pass
        return 0, ""

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_cpu_count() -> Optional[int]:
    import os
    try:
        return os.cpu_count()
    except Exception:
        return None
