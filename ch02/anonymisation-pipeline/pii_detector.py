"""
pii_detector.py  —  12-type PII detection engine
AI Fortress · Chapter 2 · Code Sample 2.B

Scans text columns in a pandas DataFrame for personally identifiable
information using regex patterns and basic heuristics.  Returns a structured
PIIFindings object suitable for downstream anonymisation decisions and audit.

Supported PII types:
  EMAIL, PHONE_UK, PHONE_US, SSN, CREDIT_CARD, IP_ADDRESS,
  NHS_NUMBER, NPI_NUMBER, DATE_OF_BIRTH, POSTCODE_UK, POSTCODE_US,
  PASSPORT_UK, IBAN
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple

import pandas as pd


class PIIType(str, Enum):
    EMAIL        = "email"
    PHONE_UK     = "phone_uk"
    PHONE_US     = "phone_us"
    SSN          = "ssn"
    CREDIT_CARD  = "credit_card"
    IP_ADDRESS   = "ip_address"
    NHS_NUMBER   = "nhs_number"
    NPI_NUMBER   = "npi_number"
    DATE_OF_BIRTH = "date_of_birth"
    POSTCODE_UK  = "postcode_uk"
    POSTCODE_US  = "postcode_us"
    PASSPORT_UK  = "passport_uk"
    IBAN         = "iban"


# Compiled regex patterns
_PATTERNS: Dict[PIIType, re.Pattern] = {
    PIIType.EMAIL:        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    PIIType.PHONE_UK:     re.compile(r"\b(?:(?:\+44|0044|0)[\s\-]?(?:\d[\s\-]?){9,10})\b"),
    PIIType.PHONE_US:     re.compile(r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"),
    PIIType.SSN:          re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    PIIType.CREDIT_CARD:  re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    PIIType.IP_ADDRESS:   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    PIIType.NHS_NUMBER:   re.compile(r"\b\d{3}[\s\-]?\d{3}[\s\-]?\d{4}\b"),
    PIIType.NPI_NUMBER:   re.compile(r"\b\d{10}\b"),
    PIIType.DATE_OF_BIRTH: re.compile(r"\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b"),
    PIIType.POSTCODE_UK:  re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[ABD-HJLNP-UW-Z]{2}\b", re.IGNORECASE),
    PIIType.POSTCODE_US:  re.compile(r"\b\d{5}(?:[-\s]\d{4})?\b"),
    PIIType.PASSPORT_UK:  re.compile(r"\b[0-9]{9}\b"),
    PIIType.IBAN:         re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
}


@dataclass
class PIIFinding:
    column:    str
    row_index: int
    pii_type:  PIIType
    matched:   str        # the matched text (may be partially masked in logs)
    start:     int
    end:       int


@dataclass
class PIIFindings:
    findings:       List[PIIFinding] = field(default_factory=list)
    columns_scanned: List[str]       = field(default_factory=list)
    rows_scanned:   int              = 0

    def count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.pii_type.value] = counts.get(f.pii_type.value, 0) + 1
        return counts

    def affected_columns(self) -> List[str]:
        return sorted(set(f.column for f in self.findings))

    def has_pii(self) -> bool:
        return len(self.findings) > 0

    def summary(self) -> str:
        if not self.findings:
            return f"No PII detected in {self.rows_scanned} rows across {len(self.columns_scanned)} columns."
        lines = [
            f"PII DETECTED — {len(self.findings)} instances across "
            f"{len(self.affected_columns())} columns ({self.rows_scanned} rows scanned):"
        ]
        for pii_type, count in sorted(self.count_by_type().items()):
            lines.append(f"  {pii_type:<20} {count:>5} instances")
        lines.append(f"  Affected columns: {', '.join(self.affected_columns())}")
        return "\n".join(lines)


class PIIDetector:
    """
    Regex-based PII detector for pandas DataFrames.

    Note: regex detection has both false positives (e.g., NPI vs NHS patterns
    overlap with random 10-digit numbers) and false negatives (novel formats).
    Use this as a first-pass scanner, not a definitive classifier.
    Complement with entity recognition models for higher recall on free text.
    """

    def __init__(self, pii_types: List[PIIType] | None = None):
        """Restrict scanning to specific PII types, or scan all if None."""
        self.active_types = pii_types or list(PIIType)

    def scan_text(self, text: str, column: str = "", row_index: int = 0) -> List[PIIFinding]:
        """Scan a single text string for all active PII types."""
        if not isinstance(text, str):
            return []
        findings: List[PIIFinding] = []
        for pii_type in self.active_types:
            pattern = _PATTERNS[pii_type]
            for match in pattern.finditer(text):
                findings.append(PIIFinding(
                    column    = column,
                    row_index = row_index,
                    pii_type  = pii_type,
                    matched   = match.group(),
                    start     = match.start(),
                    end       = match.end(),
                ))
        return findings

    def scan_dataframe(
        self,
        df:      "pd.DataFrame",
        columns: List[str] | None = None,
    ) -> PIIFindings:
        """Scan specified columns (or all string columns) of a DataFrame."""
        target_cols = columns or [c for c in df.columns if df[c].dtype == object]
        findings    = PIIFindings(columns_scanned=target_cols, rows_scanned=len(df))

        for col in target_cols:
            if col not in df.columns:
                continue
            for idx, value in df[col].items():
                findings.findings.extend(self.scan_text(str(value) if value is not None else "", col, int(idx)))

        return findings

    def redact_text(self, text: str, replacement: str = "[REDACTED]") -> Tuple[str, List[PIIFinding]]:
        """Redact all PII findings from a text string in-place."""
        findings = self.scan_text(text)
        # Process in reverse order to preserve string indices
        result = text
        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            result = result[:finding.start] + replacement + result[finding.end:]
        return result, findings
