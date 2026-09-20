import pytest
from unittest.mock import patch, MagicMock
from presidio_analyzer import RecognizerResult
from app.middleware.pii_engine import _scan_text, get_analyzer, pii_scan_response
from app.policies import HEALTHCARE_POLICY, FINTECH_POLICY, GOVTECH_POLICY, LEGAL_HR_POLICY

pytestmark = pytest.mark.asyncio


class TestHealthcarePII:
    def test_detects_ssn(self):
        # Not 123-45-6789: Presidio deliberately rejects that well-known sample SSN.
        text = "Patient SSN: 536-90-4399 needs follow-up."
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
    """PH recognizers go through Presidio: indexed placeholders, rehydratable, audited."""

    def test_detects_ph_tin(self):
        masked, detected, ph_map = _scan_text("TIN: 123-456-789-000 for tax filing.", GOVTECH_POLICY.scan_entities)
        assert "PH_TIN" in detected
        assert "[PH_TIN_1]" in masked
        assert ph_map["[PH_TIN_1]"] == "123-456-789-000"

    def test_detects_ph_tin_without_branch_code(self):
        masked, detected, _ = _scan_text("My TIN is 123-456-789.", GOVTECH_POLICY.scan_entities)
        assert "PH_TIN" in detected
        assert "123-456-789" not in masked

    def test_detects_ph_sss(self):
        masked, detected, _ = _scan_text("SSS number: 12-3456789-0", GOVTECH_POLICY.scan_entities)
        assert "PH_SSS" in detected
        assert "[PH_SSS_1]" in masked

    def test_detects_philsys(self):
        masked, detected, _ = _scan_text("PhilSys ID: 1234567890123456", GOVTECH_POLICY.scan_entities)
        assert "PH_PHILSYS" in detected
        assert "1234567890123456" not in masked

    def test_detects_philsys_dashed(self):
        masked, detected, _ = _scan_text("PhilID PCN 1234-5678-9012-3456", GOVTECH_POLICY.scan_entities)
        assert "1234-5678-9012-3456" not in masked

    def test_luhn_valid_card_labelled_credit_card_not_philsys(self):
        """A real card number must not be recorded as a PhilSys ID in the audit trail."""
        masked, detected, _ = _scan_text("Card 4111111111111111 was declined.", GOVTECH_POLICY.scan_entities)
        assert "CREDIT_CARD" in detected
        assert "PH_PHILSYS" not in detected
        assert "4111111111111111" not in masked

    def test_detects_ph_local_mobile_number(self):
        """Presidio's default phone regions omit PH; local 09XX numbers must be caught."""
        masked, detected, _ = _scan_text("Text me at 09171234567 please.", GOVTECH_POLICY.scan_entities)
        assert "PHONE_NUMBER" in detected
        assert "09171234567" not in masked

    def test_particle_surname_is_one_placeholder(self):
        """'Juan dela Cruz' must mask as one PERSON, not '[PERSON_1] dela [PERSON_2]'."""
        masked, detected, ph_map = _scan_text("Please call Juan dela Cruz at the office.", GOVTECH_POLICY.scan_entities)
        assert "PERSON" in detected
        assert ph_map["[PERSON_1]"] == "Juan dela Cruz"
        assert "[PERSON_2]" not in masked
        assert " dela " not in masked

    def test_particle_surname_round_trips_through_rehydration(self):
        from app.middleware.pii_engine import rehydrate_pii
        text = "Ma. Cristina de los Santos filed the claim."
        masked, _, ph_map = _scan_text(text, GOVTECH_POLICY.scan_entities)
        assert "Cristina" not in masked
        restored, n = rehydrate_pii(masked, ph_map)
        assert restored == text
        assert n >= 1

    def test_lowercase_text_not_swallowed_by_name_pattern(self):
        masked, _, _ = _scan_text("the report is de facto late", GOVTECH_POLICY.scan_entities)
        assert masked == "the report is de facto late"


class TestPolicyCustomRecognizers:
    def test_scan_entities_include_custom_recognizers(self):
        assert "NPI" in HEALTHCARE_POLICY.scan_entities
        assert "ROUTING_NUMBER" in FINTECH_POLICY.scan_entities
        assert "BAR_NUMBER" in LEGAL_HR_POLICY.scan_entities
        assert GOVTECH_POLICY.scan_entities.count("PERSON") == 1

    def test_custom_entity_is_indexed_and_rehydratable(self):
        """Formerly a bare re.sub -> '[NPI]': not indexed, not in the map, not audited."""
        masked, detected, ph_map = _scan_text("Provider NPI 1234567893 on file.", HEALTHCARE_POLICY.scan_entities)
        assert "NPI" in detected
        assert "[NPI_1]" in masked
        assert ph_map["[NPI_1]"] == "1234567893"


class TestScanOffloadedFromEventLoop:
    async def test_scan_runs_in_worker_thread(self):
        """Presidio must not run on the event loop thread."""
        import threading
        from app.middleware.pii_engine import scan_text_async

        seen = {}

        def _analyze(**kwargs):
            seen["thread"] = threading.current_thread()
            return []

        with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
            mock_fn.return_value = MagicMock(analyze=MagicMock(side_effect=_analyze))
            masked, detected, ph_map = await scan_text_async("hello", ["PERSON"])

        assert (masked, detected, ph_map) == ("hello", [], {})
        assert seen["thread"] is not threading.main_thread()

    async def test_worker_thread_errors_propagate_for_fail_closed(self):
        from app.middleware.pii_engine import scan_text_async
        with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
            mock_fn.return_value = MagicMock(analyze=MagicMock(side_effect=RuntimeError("boom")))
            with pytest.raises(RuntimeError):
                await scan_text_async("hello", ["PERSON"])


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
                        "X-VisorShield-User": "test-user-1",
                    },
                )

        assert resp.status_code == 500
        assert resp.json()["detail"]["error"] == "pii_scan_failed"

    async def test_response_pii_scan_error_is_fail_closed(self):
        """
        A response-scan error must never let raw LLM output through: the scan
        raises, and the response scanner substitutes its safe placeholder.
        """
        from types import SimpleNamespace
        from app.middleware.response_scanner import scan_response, _SCAN_FAILURE_PLACEHOLDER

        raw = "Call dr.jones@clinic.org for results."
        with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
            mock_fn.return_value = MagicMock(analyze=MagicMock(side_effect=RuntimeError("boom")))

            with pytest.raises(RuntimeError):
                await pii_scan_response(raw, "healthcare")

            request = SimpleNamespace(
                headers={"X-Industry-Type": "healthcare"},
                state=SimpleNamespace(
                    jwt_claims={"industry_type": "healthcare", "org_id": "org-1"},
                    request_id="req-1",
                    pipeline_timing={},
                ),
            )
            result = await scan_response(raw, request)

        assert result == _SCAN_FAILURE_PLACEHOLDER
        assert "dr.jones@clinic.org" not in result
        assert request.state.response_pii_detected == []
