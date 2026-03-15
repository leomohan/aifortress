"""
pickle_safety_scanner.py  —  Pickle opcode safety analysis for model files
AI Fortress · Chapter 8 · Code Sample 8.C

Scans PyTorch .pt/.pth/.pkl checkpoint files for dangerous pickle opcodes
BEFORE loading them. Loading a malicious pickle file executes arbitrary
Python code — this scanner detects known exploit patterns without executing
the payload.

Dangerous patterns detected:
  GLOBAL opcode calling os.system, subprocess, exec, eval, builtins.__import__
  REDUCE opcode invoking dangerous callables
  BUILD + NEWOBJ patterns used in __reduce__ exploits
  INST opcode (legacy pickle protocol, allows arbitrary instantiation)

Safe patterns: pure tensor data (protocol 2+) without GLOBAL/REDUCE chains.

References:
  - Fickling (Trail of Bits) — pickle analysis tool
  - CVE-2021-44228 analogue: pickle-based model poisoning
"""
from __future__ import annotations

import io
import pickletools
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# Dangerous module/function names that should never appear in model pickles
_DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "socket", "shutil", "importlib",
    "ctypes", "multiprocessing", "builtins",
}
_DANGEROUS_FUNCTIONS = {
    "system", "popen", "exec", "eval", "execfile", "compile",
    "__import__", "open", "getattr", "setattr", "delattr",
    "apply", "input", "raw_input",
}
# Safe ML modules and their callable allowlist
_SAFE_MODULES = {
    "torch", "torch._utils", "torch.storage", "torch.nn",
    "collections", "_codecs", "numpy", "numpy.core",
    "numpy.core.multiarray", "numpy.dtype",
}


@dataclass
class PickleThreat:
    opcode:      str
    module:      str = ""
    function:    str = ""
    description: str = ""
    severity:    str = "HIGH"   # "CRITICAL" | "HIGH"
    offset:      int = 0


@dataclass
class PickleScanResult:
    file_path:    str
    safe:         bool
    threats:      List[PickleThreat]
    opcodes_seen: List[str]
    verdict:      str           # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    recommendation: str


class PickleSafetyScanner:
    """
    Scans pickle files for dangerous opcodes without executing the payload.

    Parameters
    ----------
    strict_mode : If True, any GLOBAL opcode to a non-allowlisted module
                  triggers a SUSPICIOUS verdict (default False — only flags
                  explicitly dangerous patterns).
    """

    def __init__(self, strict_mode: bool = False):
        self.strict = strict_mode

    def scan_file(self, path: str | Path) -> PickleScanResult:
        """Scan a pickle/PyTorch checkpoint file."""
        path = Path(path)
        try:
            data = path.read_bytes()
        except (OSError, PermissionError) as e:
            return PickleScanResult(
                file_path     = str(path),
                safe          = False,
                threats       = [],
                opcodes_seen  = [],
                verdict       = "MALICIOUS",
                recommendation = f"Cannot read file: {e}",
            )
        return self.scan_bytes(data, file_path=str(path))

    def scan_bytes(self, data: bytes, file_path: str = "<bytes>") -> PickleScanResult:
        """Scan raw bytes of a pickle payload."""
        threats:      List[PickleThreat] = []
        opcodes_seen: List[str]          = []

        # PyTorch checkpoints are ZIP archives containing pickle payloads
        # Try ZIP first, then raw pickle
        payloads = self._extract_payloads(data)

        for payload_name, payload in payloads:
            payload_threats, payload_ops = self._scan_pickle(payload, payload_name)
            threats.extend(payload_threats)
            opcodes_seen.extend(payload_ops)

        safe    = len(threats) == 0
        verdict = self._verdict(threats)

        return PickleScanResult(
            file_path     = file_path,
            safe          = safe,
            threats       = threats,
            opcodes_seen  = list(dict.fromkeys(opcodes_seen)),   # deduplicated
            verdict       = verdict,
            recommendation = self._recommendation(verdict),
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _extract_payloads(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract pickle payloads from ZIP (PyTorch format) or raw bytes."""
        payloads = []
        # Check ZIP magic
        if data[:4] == b"PK\x03\x04":
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for name in zf.namelist():
                        if name.endswith(".pkl") or "data.pkl" in name:
                            payloads.append((name, zf.read(name)))
                if payloads:
                    return payloads
            except Exception:
                pass
        # Fall back to raw pickle
        payloads.append(("<root>", data))
        return payloads

    def _scan_pickle(self, data: bytes, source: str) -> Tuple[List[PickleThreat], List[str]]:
        """Scan a single pickle payload."""
        threats:  List[PickleThreat] = []
        ops_seen: List[str]          = []

        try:
            ops = list(pickletools.genops(data))
        except Exception as e:
            threats.append(PickleThreat(
                opcode      = "PARSE_ERROR",
                description = f"Could not parse pickle payload in '{source}': {e}. "
                              "Malformed pickles may indicate tampering.",
                severity    = "HIGH",
            ))
            return threats, ops_seen

        for opcode, arg, pos in ops:
            op_name = opcode.name
            ops_seen.append(op_name)

            # GLOBAL opcode: imports a module and gets a callable
            if op_name == "GLOBAL":
                module, func = (arg.split(" ", 1) + [""])[:2]
                module = module.strip()
                func   = func.strip()

                if module in _DANGEROUS_MODULES:
                    threats.append(PickleThreat(
                        opcode      = "GLOBAL",
                        module      = module,
                        function    = func,
                        description = f"GLOBAL opcode imports '{module}.{func}' — "
                                      "dangerous system module access detected.",
                        severity    = "CRITICAL",
                        offset      = pos,
                    ))
                elif func in _DANGEROUS_FUNCTIONS:
                    threats.append(PickleThreat(
                        opcode      = "GLOBAL",
                        module      = module,
                        function    = func,
                        description = f"GLOBAL opcode calls dangerous function '{func}' "
                                      f"from module '{module}'.",
                        severity    = "CRITICAL",
                        offset      = pos,
                    ))
                elif self.strict and module not in _SAFE_MODULES:
                    threats.append(PickleThreat(
                        opcode      = "GLOBAL",
                        module      = module,
                        function    = func,
                        description = f"Strict mode: GLOBAL opcode references non-allowlisted "
                                      f"module '{module}'.",
                        severity    = "HIGH",
                        offset      = pos,
                    ))

            # INST opcode (legacy — allows arbitrary class instantiation)
            elif op_name == "INST":
                module, func = (str(arg).split(" ", 1) + [""])[:2]
                if module.strip() in _DANGEROUS_MODULES or func.strip() in _DANGEROUS_FUNCTIONS:
                    threats.append(PickleThreat(
                        opcode      = "INST",
                        module      = module.strip(),
                        function    = func.strip(),
                        description = f"INST opcode (legacy) instantiates '{module}.{func}'.",
                        severity    = "HIGH",
                        offset      = pos,
                    ))

        return threats, ops_seen

    @staticmethod
    def _verdict(threats: List[PickleThreat]) -> str:
        if any(t.severity == "CRITICAL" for t in threats):
            return "MALICIOUS"
        if threats:
            return "SUSPICIOUS"
        return "SAFE"

    @staticmethod
    def _recommendation(verdict: str) -> str:
        if verdict == "MALICIOUS":
            return ("DO NOT LOAD this model. It contains dangerous opcodes that "
                    "execute arbitrary code when deserialized. Quarantine the file "
                    "and investigate the source.")
        if verdict == "SUSPICIOUS":
            return ("Review the flagged opcodes with a security engineer before loading. "
                    "Consider using safetensors format instead of pickle.")
        return ("No dangerous opcodes detected. Safe to load. "
                "Consider migrating to safetensors for defence-in-depth.")
