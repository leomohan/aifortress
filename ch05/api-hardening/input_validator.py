"""
input_validator.py  —  Inference request schema validation
AI Fortress · Chapter 5 · Code Sample 5.A

Validates ML API request payloads before they reach the model.
Prevents:
  - Out-of-memory attacks via oversized tensors
  - Undefined-behaviour exploits via wrong dtypes
  - Boundary-probing via carefully crafted extreme values
  - DoS via computationally expensive long sequences (LLMs)
  - Injection via unexpected extra fields
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import numpy as np


class InputValidationError(ValueError):
    """Raised when a request payload fails validation."""
    def __init__(self, field: str, reason: str):
        self.field  = field
        self.reason = reason
        super().__init__(f"Input validation failed on '{field}': {reason}")


@dataclass
class InputSpec:
    """Schema definition for a single ML API endpoint's accepted inputs."""
    # Tensor / array constraints
    max_shape:       Optional[List[int]] = None    # per-dimension max (None = unconstrained)
    min_shape:       Optional[List[int]] = None
    allowed_dtypes:  Optional[List[str]] = None    # e.g. ["float32", "int64"]
    value_range:     Optional[tuple]     = None    # (min_val, max_val)

    # Text / sequence constraints (for NLP endpoints)
    max_tokens:      Optional[int] = None
    max_chars:       Optional[int] = None
    allowed_fields:  Optional[Set[str]] = None     # whitelist of request body fields
    required_fields: Set[str]           = field(default_factory=set)

    # Budget constraints
    max_batch_size:  int  = 32
    max_payload_bytes: int = 10 * 1024 * 1024   # 10 MB

    # Value guards
    reject_nan:      bool = True
    reject_inf:      bool = True


class InputValidator:
    """
    Validates inference request payloads against an InputSpec.
    All validation is fail-fast: raises InputValidationError on first violation.
    """

    def validate(self, payload: Dict[str, Any], spec: InputSpec) -> None:
        """
        Validate `payload` against `spec`.
        Raises InputValidationError on any violation.
        """
        # ── Required fields ───────────────────────────────────────────────
        for req in spec.required_fields:
            if req not in payload:
                raise InputValidationError(req, f"Required field '{req}' is missing")

        # ── Allowed fields whitelist ──────────────────────────────────────
        if spec.allowed_fields is not None:
            extra = set(payload.keys()) - spec.allowed_fields
            if extra:
                raise InputValidationError(
                    "*", f"Unexpected fields in request: {sorted(extra)}. "
                         "Only allowed fields are: " + str(sorted(spec.allowed_fields))
                )

        # ── Per-field validation ──────────────────────────────────────────
        for field_name, value in payload.items():
            self._validate_value(field_name, value, spec)

    def _validate_value(
        self,
        field_name: str,
        value:      Any,
        spec:       InputSpec,
    ) -> None:
        # String / text inputs
        if isinstance(value, str):
            if spec.max_chars and len(value) > spec.max_chars:
                raise InputValidationError(
                    field_name,
                    f"String length {len(value)} exceeds max_chars={spec.max_chars}"
                )
            # Rough token estimate (word-level) for max_tokens guard
            if spec.max_tokens:
                n_tokens = len(value.split())
                if n_tokens > spec.max_tokens:
                    raise InputValidationError(
                        field_name,
                        f"Estimated token count {n_tokens} exceeds max_tokens={spec.max_tokens}"
                    )
            return

        # List / nested array → convert to numpy for shape checks
        if isinstance(value, (list, tuple)):
            try:
                value = np.array(value)
            except (ValueError, TypeError):
                raise InputValidationError(field_name, "Cannot convert list payload to array")

        if isinstance(value, np.ndarray):
            self._validate_array(field_name, value, spec)

        # Scalar numeric
        elif isinstance(value, (int, float)):
            if spec.value_range:
                lo, hi = spec.value_range
                if not (lo <= value <= hi):
                    raise InputValidationError(
                        field_name, f"Value {value} outside allowed range [{lo}, {hi}]"
                    )

    def _validate_array(self, field_name: str, arr: np.ndarray, spec: InputSpec) -> None:
        # Dtype
        if spec.allowed_dtypes:
            dtype_str = str(arr.dtype)
            if dtype_str not in spec.allowed_dtypes:
                raise InputValidationError(
                    field_name,
                    f"dtype '{dtype_str}' not in allowed dtypes {spec.allowed_dtypes}"
                )

        # Shape bounds
        if spec.max_shape:
            if len(arr.shape) != len(spec.max_shape):
                raise InputValidationError(
                    field_name,
                    f"Array has {len(arr.shape)} dims, expected {len(spec.max_shape)}"
                )
            for i, (dim, max_dim) in enumerate(zip(arr.shape, spec.max_shape)):
                if dim > max_dim:
                    raise InputValidationError(
                        field_name,
                        f"Dimension {i} size {dim} exceeds max {max_dim}"
                    )

        if spec.min_shape:
            if len(arr.shape) == len(spec.min_shape):
                for i, (dim, min_dim) in enumerate(zip(arr.shape, spec.min_shape)):
                    if dim < min_dim:
                        raise InputValidationError(
                            field_name,
                            f"Dimension {i} size {dim} below min {min_dim}"
                        )

        # Batch size
        if arr.ndim >= 1 and arr.shape[0] > spec.max_batch_size:
            raise InputValidationError(
                field_name,
                f"Batch size {arr.shape[0]} exceeds max_batch_size={spec.max_batch_size}"
            )

        # NaN / Inf
        arr_float = arr.astype(float, copy=False)
        if spec.reject_nan and np.isnan(arr_float).any():
            raise InputValidationError(field_name, "Array contains NaN values")
        if spec.reject_inf and np.isinf(arr_float).any():
            raise InputValidationError(field_name, "Array contains Inf values")

        # Value range
        if spec.value_range:
            lo, hi = spec.value_range
            if arr_float.min() < lo or arr_float.max() > hi:
                raise InputValidationError(
                    field_name,
                    f"Array values outside allowed range [{lo}, {hi}] "
                    f"(got min={arr_float.min():.4g}, max={arr_float.max():.4g})"
                )
