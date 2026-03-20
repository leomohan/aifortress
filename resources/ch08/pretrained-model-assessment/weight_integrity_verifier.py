"""
weight_integrity_verifier.py  —  SHA-256 manifest verification for model weights
AI Fortress · Chapter 8 · Code Sample 8.C

Verifies that model weight files match their expected checksums from a
manifest (compatible with HuggingFace pytorch_model.bin.index.json format
and custom AI Fortress weight manifests).

Detects:
  - Corrupted or truncated files (size mismatch)
  - Substituted weight files (SHA-256 mismatch)
  - Missing weight shards
  - Extra unexpected files in the model directory
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class WeightFileResult:
    filename:      str
    status:        str          # "OK" | "MISSING" | "CORRUPTED" | "UNEXPECTED"
    expected_sha256: str = ""
    actual_sha256:   str = ""
    expected_size:   int = 0
    actual_size:     int = 0


@dataclass
class WeightIntegrityReport:
    model_dir:    str
    total_files:  int
    ok:           int
    corrupted:    int
    missing:      int
    unexpected:   int
    results:      List[WeightFileResult]
    overall_pass: bool

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Weight integrity: {self.ok}/{self.total_files} OK, "
            f"{self.corrupted} corrupted, {self.missing} missing, "
            f"{self.unexpected} unexpected."
        )


class WeightIntegrityVerifier:
    """
    Verifies model weight files against a SHA-256 manifest.

    Parameters
    ----------
    allow_unexpected : If True, extra files in the directory are not flagged
                       as UNEXPECTED (useful when model dir contains configs).
    """

    def __init__(self, allow_unexpected: bool = False):
        self.allow_unexpected = allow_unexpected

    def verify_directory(
        self,
        model_dir: str | Path,
        manifest:  dict,
    ) -> WeightIntegrityReport:
        """
        Verify all files in `model_dir` against `manifest`.

        Manifest format:
          {
            "files": {
              "pytorch_model.bin": {"sha256": "...", "size": 123456},
              "model-00001-of-00002.safetensors": {"sha256": "...", "size": 789}
            }
          }
        """
        model_dir = Path(model_dir)
        results:  List[WeightFileResult] = []
        expected_files = manifest.get("files", {})

        for filename, meta in expected_files.items():
            fpath = model_dir / filename
            expected_sha = meta.get("sha256", "")
            expected_sz  = meta.get("size", 0)

            if not fpath.exists():
                results.append(WeightFileResult(
                    filename       = filename,
                    status         = "MISSING",
                    expected_sha256 = expected_sha,
                    expected_size   = expected_sz,
                ))
                continue

            actual_sz  = fpath.stat().st_size
            actual_sha = self._hash_file(fpath)
            status = "OK" if (actual_sha == expected_sha and
                              (expected_sz == 0 or actual_sz == expected_sz)) else "CORRUPTED"
            results.append(WeightFileResult(
                filename        = filename,
                status          = status,
                expected_sha256 = expected_sha,
                actual_sha256   = actual_sha,
                expected_size   = expected_sz,
                actual_size     = actual_sz,
            ))

        # Check for unexpected files
        if not self.allow_unexpected and model_dir.is_dir():
            known = set(expected_files.keys())
            weight_exts = {".bin", ".pt", ".pth", ".pkl", ".safetensors", ".gguf"}
            for fpath in model_dir.iterdir():
                if fpath.suffix in weight_exts and fpath.name not in known:
                    results.append(WeightFileResult(
                        filename    = fpath.name,
                        status      = "UNEXPECTED",
                        actual_sha256 = self._hash_file(fpath),
                        actual_size   = fpath.stat().st_size,
                    ))

        ok          = sum(1 for r in results if r.status == "OK")
        corrupted   = sum(1 for r in results if r.status == "CORRUPTED")
        missing     = sum(1 for r in results if r.status == "MISSING")
        unexpected  = sum(1 for r in results if r.status == "UNEXPECTED")

        return WeightIntegrityReport(
            model_dir    = str(model_dir),
            total_files  = len(results),
            ok           = ok,
            corrupted    = corrupted,
            missing      = missing,
            unexpected   = unexpected,
            results      = results,
            overall_pass = corrupted == 0 and missing == 0 and unexpected == 0,
        )

    def verify_file(
        self,
        path:         str | Path,
        expected_sha: str,
        expected_size: int = 0,
    ) -> WeightFileResult:
        """Verify a single weight file."""
        path = Path(path)
        if not path.exists():
            return WeightFileResult(filename=path.name, status="MISSING",
                                    expected_sha256=expected_sha, expected_size=expected_size)
        actual_sha = self._hash_file(path)
        actual_sz  = path.stat().st_size
        status = "OK" if (actual_sha == expected_sha and
                          (expected_size == 0 or actual_sz == expected_size)) else "CORRUPTED"
        return WeightFileResult(
            filename        = path.name,
            status          = status,
            expected_sha256 = expected_sha,
            actual_sha256   = actual_sha,
            expected_size   = expected_size,
            actual_size     = actual_sz,
        )

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
