import pytest
from unittest.mock import patch, MagicMock
from presidio_analyzer import RecognizerResult
from app.middleware.pii_engine import _scan_text, get_analyzer, pii_scan_response
from app.policies import HEALTHCARE_POLICY, FINTECH_POLICY, GOVTECH_POLICY, LEGAL_HR_POLICY

pytestmark = pytest.mark.asyncio


class TestHealthcarePII:
    def test_detects_ssn(self):
        text = "Patient SSN: 123-45-6789 needs follow-up."
        _, detected, _ = _scan_text(text, HEALTHCARE_POLICY.pii_entities)
        assert "US_SSN" in detected

    def test_detects_email(self):
        text = "Contact dr.smith@hospital.com for results."
        _, detected, _ = _scan_text(text, HEALTHCARE_POLICY.pii_entities)
        assert "EMAIL_ADDRESS" in detected

    def test_detects_phone(self):
        text = "Call the patient at (555) 867-5309."
        _, detected, _ = _scan_text(text, HEALTHCARE_POLICY.pii_entities)
        assert "PHONE_NUMBER" in detected

    def test_masking_replaces_values(self):
        text = "Email dr.jones@clinic.org for appointment."
        masked, detected, _ = _scan_text(text, HEALTHCARE_POLICY.pii_entities)
        assert "dr.jones@clinic.org" not in masked
        assert "[EMAIL_ADDRESS_1]" in masked


class TestFintechPII:
    def test_detects_credit_card(self):
        text = "Charge card 4111 1111 1111 1111 for $500."
        _, detected, _ = _scan_text(text, FINTECH_POLICY.pii_entities)
        assert "CREDIT_CARD" in detected

    def test_detects_email(self):
        text = "Send invoice to user@bank.com"
        _, detected, _ = _scan_text(text, FINTECH_POLICY.pii_entities)
        assert "EMAIL_ADDRESS" in detected


class TestGovtechPII:
    def test_detects_ph_tin(self):
        text = "TIN: 123-456-789-000 for tax filing."
        from app.middleware.pii_engine import _apply_regex_patterns
        text_with_regex = _apply_regex_patterns(text, GOVTECH_POLICY.regex_patterns)
        assert "[PH_TIN]" in text_with_regex

    def test_detects_ph_sss(self):
        text = "SSS number: 12-3456789-0"
        from app.middleware.pii_engine import _apply_regex_patterns
        text_with_regex = _apply_regex_patterns(text, GOVTECH_POLICY.regex_patterns)
        assert "[PH_SSS]" in text_with_regex

    def test_detects_philsys(self):
        text = "PhilSys ID: 1234567890123456"
        from app.middleware.pii_engine import _apply_regex_patterns
        text_with_regex = _apply_regex_patterns(text, GOVTECH_POLICY.regex_patterns)
        assert "[PH_PHILSYS]" in text_with_regex


class TestLegalHRPII:
    def test_detects_person(self):
        text = "John Smith applied for the senior attorney role."
        _, detected, _ = _scan_text(text, LEGAL_HR_POLICY.pii_entities)
        assert "PERSON" in detected

    def test_detects_email(self):
        text = "Submit resume to hr@lawfirm.com"
        _, detected, _ = _scan_text(text, LEGAL_HR_POLICY.pii_entities)
        assert "EMAIL_ADDRESS" in detected


class TestFailClosed:
    async def test_pii_engine_fail_closed(self):
        """If Presidio raises, pii_scan_request must return HTTP 500."""
        from fastapi import HTTPException
        from unittest.mock import AsyncMock
        from fastapi.testclient import TestClient
        from app.main import app

        with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.side_effect = RuntimeError("Presidio crashed")
            mock_fn.return_value = mock_analyzer

            import httpx
            from httpx import AsyncClient, ASGITransport
            from tests.conftest import make_jwt

            token = make_jwt()
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "test"}]},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-Industry-Type": "healthcare",
                    },
                )

        assert resp.status_code == 500
        assert resp.json()["detail"]["error"] == "pii_scan_failed"

    async def test_response_pii_scan_error_returns_original(self):
        """Response scanner failure returns original text (not fail-closed — just logs)."""
        with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.side_effect = RuntimeError("boom")
            mock_fn.return_value = mock_analyzer

            text, detected = await pii_scan_response("some sensitive text", "healthcare")

        assert text == "some sensitive text"
        assert detected == []
