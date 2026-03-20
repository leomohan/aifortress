"""
data_lineage.py  —  Dataset version, pipeline, and split recorder
AI Fortress · Chapter 4 · Code Sample 4.C
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class DataLineage:
    dataset_id:          str
    dataset_version:     str
    dataset_sha256:      str = ""    # SHA-256 of the dataset manifest or archive
    source_description:  str = ""
    preprocessing_steps: List[str] = field(default_factory=list)
    split_ratios:        Dict[str, float] = field(default_factory=dict)  # train/val/test
    n_train:             Optional[int] = None
    n_val:               Optional[int] = None
    n_test:              Optional[int] = None
    anonymisation_applied: bool = False
    gdpr_lawful_basis:   str = ""
    dpia_ref:            str = ""    # reference to DPIA document
    provenance_chain_ref: str = ""   # reference to Ch.1 provenance chain

    def to_dict(self) -> dict:
        return asdict(self)
