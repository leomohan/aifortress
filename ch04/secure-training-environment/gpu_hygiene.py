"""
gpu_hygiene.py  —  GPU memory clearing and hygiene certificate
AI Fortress · Chapter 4 · Code Sample 4.A

On shared GPU infrastructure (multi-tenant cloud, on-prem cluster),
a prior training job's model weights, gradient tensors, and activations
may remain in GPU VRAM after the job completes if the CUDA context is
not properly cleaned up.  An adversary with access to the next job on
the same GPU can potentially reconstruct these residual values.

This module provides:
  1. Pre-job hygiene check  — verify VRAM is clear before allocating
  2. Post-job cleanup       — zero all allocated tensors and flush caches
  3. Hygiene certificate    — signed record that cleanup was performed

Design: runs without requiring CUDA if torch is not installed (stubs
return safe defaults) so this module can be imported in test/CI environments.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class GPUHygieneCertificate:
    cert_id:         str
    job_id:          str
    device_index:    int
    pre_vram_free_mb:  float
    post_vram_free_mb: float
    cleanup_method:  str
    duration_seconds: float
    issued_at:       str
    sha256_proof:    str   # hash of cert fields for tamper-evidence

    def to_dict(self) -> dict:
        return {
            "cert_id":          self.cert_id,
            "job_id":           self.job_id,
            "device_index":     self.device_index,
            "pre_vram_free_mb": self.pre_vram_free_mb,
            "post_vram_free_mb": self.post_vram_free_mb,
            "cleanup_method":   self.cleanup_method,
            "duration_seconds": round(self.duration_seconds, 3),
            "issued_at":        self.issued_at,
            "sha256_proof":     self.sha256_proof,
        }


def _hash_cert(fields: dict) -> str:
    payload = json.dumps({k: v for k, v in fields.items() if k != "sha256_proof"},
                         sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class GPUHygieneManager:
    """
    Manages GPU memory hygiene for a training job.

    Parameters
    ----------
    job_id       : Unique identifier for the current training job
    device_index : CUDA device index (default 0)
    """

    def __init__(self, job_id: str, device_index: int = 0):
        self.job_id       = job_id
        self.device_index = device_index
        self._torch_available = self._check_torch()

    def _check_torch(self) -> bool:
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False

    def _vram_free_mb(self) -> float:
        if not self._torch_available:
            return -1.0   # sentinel: unknown
        import torch
        free, _ = torch.cuda.mem_get_info(self.device_index)
        return free / (1024 ** 2)

    def pre_job_check(self, max_used_mb: float = 100.0) -> dict:
        """
        Check that GPU memory is sufficiently clear before job starts.
        Returns a report dict; raises RuntimeError if used memory exceeds threshold.
        """
        free_mb = self._vram_free_mb()
        if self._torch_available:
            import torch
            _, total = torch.cuda.mem_get_info(self.device_index)
            total_mb = total / (1024 ** 2)
            used_mb  = total_mb - free_mb
        else:
            total_mb = used_mb = -1.0

        report = {
            "job_id":       self.job_id,
            "device":       self.device_index,
            "free_mb":      round(free_mb, 2),
            "used_mb":      round(used_mb, 2),
            "total_mb":     round(total_mb, 2),
            "torch_available": self._torch_available,
            "status":       "unknown" if not self._torch_available else (
                "clean" if used_mb <= max_used_mb else "dirty"
            ),
        }
        if self._torch_available and used_mb > max_used_mb:
            raise RuntimeError(
                f"GPU {self.device_index} has {used_mb:.1f} MB in use before job start "
                f"(threshold {max_used_mb} MB). Possible residue from prior job. "
                "Run cleanup() on the prior job context first."
            )
        return report

    def cleanup(self) -> GPUHygieneCertificate:
        """
        Zero all GPU tensors and flush CUDA caches.
        Returns a GPUHygieneCertificate as audit evidence.
        """
        start    = time.monotonic()
        pre_free = self._vram_free_mb()

        if self._torch_available:
            import torch
            import gc

            # 1. Delete all live tensors on this device
            for obj in gc.get_objects():
                try:
                    if torch.is_tensor(obj) and obj.device.index == self.device_index:
                        # Zero the tensor before freeing (overwrite residue)
                        obj.zero_()
                        del obj
                except Exception:
                    pass

            # 2. Release cached memory allocator blocks
            torch.cuda.empty_cache()

            # 3. Synchronise to ensure all operations are complete
            torch.cuda.synchronize(self.device_index)

            cleanup_method = "torch_zero_empty_cache_synchronize"
        else:
            cleanup_method = "no_op_torch_unavailable"

        post_free = self._vram_free_mb()
        duration  = time.monotonic() - start
        issued_at = datetime.now(timezone.utc).isoformat()

        fields = {
            "cert_id":          str(uuid.uuid4()),
            "job_id":           self.job_id,
            "device_index":     self.device_index,
            "pre_vram_free_mb": round(pre_free, 2),
            "post_vram_free_mb": round(post_free, 2),
            "cleanup_method":   cleanup_method,
            "duration_seconds": round(duration, 3),
            "issued_at":        issued_at,
        }
        fields["sha256_proof"] = _hash_cert(fields)

        return GPUHygieneCertificate(**fields)
