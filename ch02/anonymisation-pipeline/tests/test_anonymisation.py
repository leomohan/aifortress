"""
tests/test_anonymisation.py  —  PII detection, k-anonymity, pseudonymisation tests
AI Fortress · Chapter 2 · Code Sample 2.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import pandas as pd
import pytest
from pii_detector import PIIDetector, PIIType
from k_anonymity import enforce_k_anonymity, enforce_l_diversity, generalise_numeric
from pseudonymiser import Pseudonymiser


class TestPIIDetector:
    def setup_method(self):
        self.det = PIIDetector()

    def test_email_detected(self):
        findings = self.det.scan_text("Contact alice@example.com for info")
        assert any(f.pii_type == PIIType.EMAIL for f in findings)

    def test_ssn_detected(self):
        findings = self.det.scan_text("SSN: 123-45-6789")
        assert any(f.pii_type == PIIType.SSN for f in findings)

    def test_credit_card_detected(self):
        findings = self.det.scan_text("Card: 4111 1111 1111 1111")
        assert any(f.pii_type == PIIType.CREDIT_CARD for f in findings)

    def test_no_pii_clean_text(self):
        findings = self.det.scan_text("The weather today is sunny and warm.")
        assert len(findings) == 0

    def test_scan_dataframe(self):
        df = pd.DataFrame({"notes": ["Call me at 07700 900123", "No PII here"],
                           "email": ["bob@test.com", ""]})
        result = self.det.scan_dataframe(df)
        assert result.has_pii()
        assert "email" in result.affected_columns() or "notes" in result.affected_columns()

    def test_redact_text(self):
        redacted, findings = self.det.redact_text("Email me at test@example.com please")
        assert "test@example.com" not in redacted
        assert "[REDACTED]" in redacted


class TestKAnonymity:
    def _make_df(self):
        return pd.DataFrame({
            "age_band": ["20-24","20-24","20-24","20-24","20-24",
                         "25-29","25-29","30-34"],
            "gender":   ["M","M","M","M","M","F","F","M"],
            "postcode": ["SW1","SW1","SW1","SW1","SW1","EC1","EC1","E1"],
            "diagnosis": ["Flu","Cold","Flu","Cold","Flu","Flu","Cold","Flu"],
        })

    def test_k5_removes_small_groups(self):
        df     = self._make_df()
        out, r = enforce_k_anonymity(df, ["age_band","gender","postcode"], k=5)
        assert r.k_achieved >= 5
        assert len(out) < len(df)

    def test_k1_keeps_all_rows(self):
        df     = self._make_df()
        out, r = enforce_k_anonymity(df, ["age_band","gender","postcode"], k=1)
        assert len(out) == len(df)

    def test_l_diversity(self):
        df      = self._make_df()
        out, r  = enforce_l_diversity(df, ["age_band","gender","postcode"],
                                       sensitive_attr="diagnosis", k=3, l=2)
        assert r.l_achieved is not None

    def test_generalise_numeric(self):
        df = pd.DataFrame({"age": [22, 27, 33, 41]})
        df = generalise_numeric(df, "age", bin_size=5)
        assert df["age"].iloc[0] == "20-24"


class TestPseudonymiser:
    def test_deterministic(self):
        p = Pseudonymiser(b"0123456789abcdef0123456789abcdef")
        assert p.pseudonymise("alice@example.com") == p.pseudonymise("alice@example.com")

    def test_different_inputs_different_tokens(self):
        p = Pseudonymiser(b"0123456789abcdef0123456789abcdef")
        assert p.pseudonymise("alice@example.com") != p.pseudonymise("bob@example.com")

    def test_different_keys_different_tokens(self):
        p1 = Pseudonymiser(b"0123456789abcdef0123456789abcdef")
        p2 = Pseudonymiser(b"fedcba9876543210fedcba9876543210")
        assert p1.pseudonymise("alice@example.com") != p2.pseudonymise("alice@example.com")

    def test_column_pseudonymisation(self):
        p  = Pseudonymiser(b"0123456789abcdef0123456789abcdef", prefix="PSE-")
        df = pd.DataFrame({"email": ["a@b.com", "c@d.com"]})
        out = p.pseudonymise_column(df, "email")
        assert all(out["email"].str.startswith("PSE-"))
        assert "a@b.com" not in out["email"].values

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="at least 16 bytes"):
            Pseudonymiser(b"tooshort")
