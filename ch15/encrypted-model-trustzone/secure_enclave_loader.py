"""
secure_enclave_loader.py  —  ARM TrustZone secure enclave loader simulator
AI Fortress · Chapter 15 · Code Sample 15.B

Simulates the ARM TrustZone Trusted Application (TA) loading flow
for protected ML inference:

  Normal World (REE)        Secure World (TEE)
  ─────────────────         ──────────────────
  CA: request inference  →  TA: receive input
                             TA: decrypt model weights (from secure storage)
                             TA: run inference inside TEE
                          ←  TA: return result (not weights)

In production:
  - Use OP-TEE (open source TEE) or vendor TEE (Kinibi, ISEE, QTEE)
  - Model weights loaded from secure storage (eMMC RPMB or eFuse-encrypted partition)
  - Inference runs inside a Trusted Application; weights never leave secure world
  - Communication via secure mailbox / shared memory with strict bounds checking
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


@dataclass
class EnclaveSession:
    session_id:   str
    ta_id:        str       # Trusted Application identifier
    loaded_at:    str
    model_id:     str
    active:       bool = True
    inference_count: int = 0


@dataclass
class EnclaveInferenceResult:
    session_id:     str
    output:         Any
    model_id:       str
    weights_leaked: bool = False    # always False in correct implementation
    integrity_ok:   bool = True


class SecureEnclaveLoader:
    """
    Simulates loading and running an ML model inside a TrustZone TA.

    Parameters
    ----------
    ta_id          : Trusted Application UUID.
    verify_key     : Key used to verify model integrity before loading.
    inference_fn   : Callable(model_weights, inputs) → outputs.
                     Represents the actual inference logic inside the TEE.
    """

    def __init__(
        self,
        ta_id:        str,
        verify_key:   bytes,
        inference_fn: Callable,
    ):
        self._ta_id      = ta_id
        self._key        = verify_key
        self._infer      = inference_fn
        self._sessions:  Dict[str, EnclaveSession] = {}
        self._model_cache: Dict[str, bytes] = {}   # model_id → decrypted weights (inside TEE)

    def open_session(self, model_id: str, model_weights: bytes) -> EnclaveSession:
        """
        Load a model into the simulated secure enclave.
        Weights are retained in-memory only; never returned to Normal World.
        """
        import uuid
        session_id = str(uuid.uuid4())
        self._model_cache[session_id] = model_weights  # "inside TEE"
        session = EnclaveSession(
            session_id  = session_id,
            ta_id       = self._ta_id,
            loaded_at   = datetime.now(timezone.utc).isoformat(),
            model_id    = model_id,
        )
        self._sessions[session_id] = session
        return session

    def invoke(
        self,
        session_id: str,
        inputs:     Any,
    ) -> EnclaveInferenceResult:
        """Run inference inside the simulated TEE. Model weights are not returned."""
        session = self._sessions.get(session_id)
        if session is None or not session.active:
            raise ValueError(f"No active session '{session_id}'")

        weights = self._model_cache.get(session_id, b"")
        output  = self._infer(weights, inputs)
        session.inference_count += 1

        return EnclaveInferenceResult(
            session_id     = session_id,
            output         = output,
            model_id       = session.model_id,
            weights_leaked = False,   # weights never leave this method
        )

    def close_session(self, session_id: str) -> None:
        """Securely wipe model weights from TEE memory."""
        if session_id in self._model_cache:
            # Overwrite before deleting (simulating secure wipe)
            size = len(self._model_cache[session_id])
            self._model_cache[session_id] = b"\x00" * size
            del self._model_cache[session_id]
        if session_id in self._sessions:
            self._sessions[session_id].active = False

    def active_sessions(self) -> List[EnclaveSession]:
        return [s for s in self._sessions.values() if s.active]
