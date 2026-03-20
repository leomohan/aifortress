"""
secure_boot_verifier.py  —  TCG event log replay and PCR verification
AI Fortress · Chapter 15 · Code Sample 15.A

Parses and replays a TCG Measured Boot Event Log to reconstruct
PCR values from recorded measurements. Detects:
  - Log tampering (reconstructed PCR ≠ reported PCR)
  - Unexpected boot components (measurements not in approved list)
  - Missing mandatory measurements (e.g. UEFI db/dbx not measured)

In a real system the event log is retrieved from the TPM's NVRAM
or from the EFI variable EFI_TCG2_PROTOCOL.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class BootEvent:
    pcr_index:    int
    event_type:   str       # e.g. "EV_EFI_VARIABLE_BOOT", "EV_EFI_ACTION"
    description:  str
    measurement:  bytes     # raw bytes being extended into the PCR


@dataclass
class BootLogVerificationResult:
    valid:              bool
    pcr_reconstructed:  Dict[int, str]    # PCR → reconstructed digest
    pcr_reported:       Dict[int, str]    # PCR → TPM-reported digest
    mismatched_pcrs:    List[int]
    unexpected_events:  List[str]
    missing_events:     List[str]
    event_count:        int
    detail:             str


class SecureBootVerifier:
    """
    Replays a TCG event log to verify secure boot integrity.

    Parameters
    ----------
    approved_components : Set of approved description strings.
                          Measurements not in this set are flagged.
    required_events     : Descriptions that MUST appear in the log.
                          Missing entries indicate incomplete measurement.
    """

    def __init__(
        self,
        approved_components: Optional[Set[str]] = None,
        required_events:     Optional[Set[str]] = None,
    ):
        self._approved = approved_components
        self._required = required_events or set()

    def verify(
        self,
        events:       List[BootEvent],
        reported_pcrs: Dict[int, str],
    ) -> BootLogVerificationResult:
        """
        Replay events to reconstruct PCR values and compare to reported values.

        Parameters
        ----------
        events        : Ordered list of boot measurement events.
        reported_pcrs : PCR values as reported by the TPM (from attestation quote).
        """
        # Replay: start from initial PCR state
        reconstructed: Dict[int, str] = {}
        for ev in events:
            current   = reconstructed.get(ev.pcr_index, "00" * 32)
            new_value = hashlib.sha256(
                bytes.fromhex(current) + ev.measurement
            ).hexdigest()
            reconstructed[ev.pcr_index] = new_value

        # PCR mismatch detection
        mismatched = [
            pcr for pcr, val in reconstructed.items()
            if reported_pcrs.get(pcr, "") != val
        ]

        # Unexpected component detection
        unexpected: List[str] = []
        if self._approved is not None:
            unexpected = [
                ev.description for ev in events
                if ev.description not in self._approved
            ]

        # Missing required events
        seen_descs = {ev.description for ev in events}
        missing    = [r for r in self._required if r not in seen_descs]

        valid  = len(mismatched) == 0 and len(unexpected) == 0 and len(missing) == 0
        detail = (
            "Boot log verified successfully." if valid
            else f"Issues: {len(mismatched)} PCR mismatch(es), "
                 f"{len(unexpected)} unexpected component(s), "
                 f"{len(missing)} missing required event(s)."
        )

        return BootLogVerificationResult(
            valid             = valid,
            pcr_reconstructed = reconstructed,
            pcr_reported      = reported_pcrs,
            mismatched_pcrs   = mismatched,
            unexpected_events = unexpected,
            missing_events    = missing,
            event_count       = len(events),
            detail            = detail,
        )
