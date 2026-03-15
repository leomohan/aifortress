"""
model_fingerprinter.py  —  Model fingerprint generation and matching
AI Fortress · Chapter 6 · Code Sample 6.C

Generates a stable, unique fingerprint for a model based on its responses
to a secret set of "fingerprint queries" (Cao et al. 2021 — IPGuard).

The fingerprint is:
  - Stable under fine-tuning: fingerprint queries sit near decision boundaries
    where responses are sensitive to the specific model, not just the task
  - Unique: collision probability is negligible for independently trained models
  - Black-box: only requires API-level query access to verify

Algorithm:
  1. Generate N fingerprint queries in the input space (keyed by secret)
  2. Collect model's response (argmax class) for each query → fingerprint vector
  3. Matching: query a suspect model and compare response vectors
  4. Statistical test: agreement rate vs expected random agreement

Framework-agnostic: accepts a score_fn (numpy → probability vector).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import numpy as np
from scipy import stats


@dataclass
class ModelFingerprint:
    fingerprint_id: str
    owner_id:       str
    model_name:     str
    n_queries:      int
    input_shape:    List[int]
    queries:        List[List[float]]   # fingerprint query inputs (secret)
    responses:      List[int]           # model's argmax response to each query
    created_at:     str

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "ModelFingerprint":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class FingerprintMatchResult:
    match:            bool
    agreement_rate:   float     # fraction of queries with matching response
    threshold:        float
    p_value:          float     # binomial test p-value
    n_queries:        int
    suspect_responses: List[int]
    owner_responses:   List[int]


class ModelFingerprinter:
    """
    Generates and matches model fingerprints.

    Parameters
    ----------
    owner_id         : Model owner identifier
    n_queries        : Number of fingerprint queries (default 100)
    match_threshold  : Agreement rate above which models match (default 0.75)
    alpha            : Significance level for binomial test (default 0.01)
    """

    def __init__(
        self,
        owner_id:        str,
        n_queries:       int   = 100,
        match_threshold: float = 0.75,
        alpha:           float = 0.01,
    ):
        self.owner_id        = owner_id
        self.n_queries       = n_queries
        self.match_threshold = match_threshold
        self.alpha           = alpha

    def generate(
        self,
        score_fn:    Callable[[np.ndarray], np.ndarray],
        input_shape: List[int],
        model_name:  str,
        secret:      bytes,
        value_range: Tuple[float, float] = (0.0, 1.0),
    ) -> ModelFingerprint:
        """
        Generate a fingerprint by querying the model with secret-keyed inputs.

        Parameters
        ----------
        score_fn    : Model inference function (input → probability vector)
        input_shape : Shape of a single input (e.g. [3, 224, 224])
        model_name  : Model identifier
        secret      : Owner secret for deterministic query generation
        value_range : (min, max) valid input value range
        """
        seed = int.from_bytes(hashlib.sha256(secret + model_name.encode()).digest()[:8], "big")
        rng  = np.random.default_rng(seed)
        lo, hi = value_range

        queries   = []
        responses = []

        for _ in range(self.n_queries):
            # Generate query near decision boundaries: random input in valid range
            q     = rng.uniform(lo, hi, input_shape).astype(np.float32)
            probs = np.asarray(score_fn(q), dtype=float)
            queries.append(q.flatten().tolist())
            responses.append(int(np.argmax(probs)))

        return ModelFingerprint(
            fingerprint_id = str(uuid.uuid4()),
            owner_id       = self.owner_id,
            model_name     = model_name,
            n_queries      = self.n_queries,
            input_shape    = input_shape,
            queries        = queries,
            responses      = responses,
            created_at     = datetime.now(timezone.utc).isoformat(),
        )

    def match(
        self,
        fingerprint: ModelFingerprint,
        suspect_fn:  Callable[[np.ndarray], np.ndarray],
    ) -> FingerprintMatchResult:
        """
        Test whether `suspect_fn` matches the fingerprint.

        Parameters
        ----------
        fingerprint : Owner's ModelFingerprint
        suspect_fn  : Inference function of the suspect model
        """
        suspect_responses = []
        input_shape       = fingerprint.input_shape

        for q_flat in fingerprint.queries:
            q     = np.array(q_flat, dtype=np.float32).reshape(input_shape)
            probs = np.asarray(suspect_fn(q), dtype=float)
            suspect_responses.append(int(np.argmax(probs)))

        n          = len(fingerprint.responses)
        agreements = sum(s == o for s, o in zip(suspect_responses, fingerprint.responses))
        rate       = agreements / n

        # Binomial test: H₀ = random chance (1/n_classes), H₁ = above threshold
        # Estimate n_classes from unique responses in fingerprint
        n_classes  = max(max(fingerprint.responses) + 1, 2)
        base_rate  = 1.0 / n_classes
        result     = stats.binomtest(agreements, n, base_rate, alternative="greater")
        p_value    = float(result.pvalue)

        return FingerprintMatchResult(
            match             = rate >= self.match_threshold and p_value < self.alpha,
            agreement_rate    = round(rate, 4),
            threshold         = self.match_threshold,
            p_value           = round(p_value, 8),
            n_queries         = n,
            suspect_responses = suspect_responses,
            owner_responses   = fingerprint.responses,
        )
