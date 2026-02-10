"""Unit tests for cloud LLM PII detectors (OpenAI, Anthropic, Gemini)."""

import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pii.cloud_llm_detector import (
    CloudLLMDetector,
    OpenAIDetector,
    AnthropicDetector,
    GeminiDetector,
    LLM_TYPE_MAPPING,
)
from src.pii.types import PIIType, PIIDetection


# ===================================================================
# GDPR Warning
# ===================================================================

class TestGDPRWarning:
    """Test GDPR data privacy warnings on initialization."""

    def test_warning_logged_when_not_acknowledged(self):
        with patch('src.pii.cloud_llm_detector.logger') as mock_logger:
            OpenAIDetector({'api_key': 'test-key'})
            warnings = [
                call for call in mock_logger.warning.call_args_list
                if 'DATA PRIVACY' in str(call)
            ]
            assert len(warnings) == 1
            assert 'GDPR' in str(warnings[0])

    def test_no_warning_when_acknowledged(self):
        with patch('src.pii.cloud_llm_detector.logger') as mock_logger:
            OpenAIDetector({
                'api_key': 'test-key',
                'data_privacy_acknowledged': True,
            })
            warnings = [
                call for call in mock_logger.warning.call_args_list
                if 'DATA PRIVACY' in str(call)
            ]
            assert len(warnings) == 0

    def test_warning_for_each_provider(self):
        for cls, name in [
            (OpenAIDetector, 'openai'),
            (AnthropicDetector, 'anthropic'),
            (GeminiDetector, 'gemini'),
        ]:
            with patch('src.pii.cloud_llm_detector.logger') as mock_logger:
                cls({'api_key': 'test-key'})
                warnings = [
                    str(call) for call in mock_logger.warning.call_args_list
                    if 'DATA PRIVACY' in str(call)
                ]
                assert len(warnings) == 1, f"No GDPR warning for {name}"


# ===================================================================
# Initialization
# ===================================================================

class TestInitialization:
    """Test provider initialization and validation."""

    def test_openai_requires_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            OpenAIDetector({})

    def test_anthropic_requires_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            AnthropicDetector({})

    def test_gemini_requires_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            GeminiDetector({})

    def test_openai_default_model(self):
        d = OpenAIDetector({'api_key': 'k', 'data_privacy_acknowledged': True})
        assert d.model == 'gpt-4o-mini'

    def test_anthropic_default_model(self):
        d = AnthropicDetector({'api_key': 'k', 'data_privacy_acknowledged': True})
        assert d.model == 'claude-sonnet-4-20250514'

    def test_gemini_default_model(self):
        d = GeminiDetector({'api_key': 'k', 'data_privacy_acknowledged': True})
        assert d.model == 'gemini-2.0-flash'

    def test_custom_model(self):
        d = OpenAIDetector({
            'api_key': 'k',
            'model': 'gpt-4',
            'data_privacy_acknowledged': True,
        })
        assert d.model == 'gpt-4'

    def test_provider_names(self):
        assert OpenAIDetector({'api_key': 'k', 'data_privacy_acknowledged': True}).get_name() == 'openai'
        assert AnthropicDetector({'api_key': 'k', 'data_privacy_acknowledged': True}).get_name() == 'anthropic'
        assert GeminiDetector({'api_key': 'k', 'data_privacy_acknowledged': True}).get_name() == 'gemini'

    def test_is_available_with_key(self):
        d = OpenAIDetector({'api_key': 'k', 'data_privacy_acknowledged': True})
        assert d.is_available() is True

    def test_openai_ssrf_validation(self):
        with pytest.raises(ValueError, match="blocked"):
            OpenAIDetector({
                'api_key': 'k',
                'base_url': 'http://169.254.169.254',
                'data_privacy_acknowledged': True,
            })


# ===================================================================
# Field-Level Detection
# ===================================================================

class TestFieldDetection:
    """Test per-field PII detection with mocked API responses."""

    @pytest.fixture
    def openai(self):
        return OpenAIDetector({'api_key': 'k', 'data_privacy_acknowledged': True})

    def test_detect_email(self, openai):
        mock_response = json.dumps({'pii': True, 'type': 'email', 'confidence': 0.95})
        with patch.object(openai, '_call_api', return_value=mock_response):
            results = openai.detect('test@example.com', 'email')
            assert len(results) == 1
            assert results[0].pii_type == PIIType.EMAIL
            assert results[0].confidence == 0.95

    def test_detect_no_pii(self, openai):
        mock_response = json.dumps({'pii': False})
        with patch.object(openai, '_call_api', return_value=mock_response):
            results = openai.detect('hello world', 'greeting')
            assert len(results) == 0

    def test_detect_ssn(self, openai):
        mock_response = json.dumps({'pii': True, 'type': 'ssn', 'confidence': 0.9})
        with patch.object(openai, '_call_api', return_value=mock_response):
            results = openai.detect('123-45-6789', 'ssn')
            assert len(results) == 1
            assert results[0].pii_type == PIIType.SSN

    def test_detect_skips_short_values(self, openai):
        results = openai.detect('ab', 'field')
        assert len(results) == 0

    def test_detect_skips_empty_values(self, openai):
        results = openai.detect('', 'field')
        assert len(results) == 0

    def test_detect_handles_api_error(self, openai):
        with patch.object(openai, '_call_api', side_effect=Exception('API error')):
            results = openai.detect('test@example.com', 'email')
            assert len(results) == 0

    def test_detect_handles_invalid_json(self, openai):
        with patch.object(openai, '_call_api', return_value='not json'):
            results = openai.detect('test@example.com', 'email')
            assert len(results) == 0

    def test_detect_handles_markdown_wrapped_json(self, openai):
        mock_response = '```json\n{"pii": true, "type": "email", "confidence": 0.9}\n```'
        with patch.object(openai, '_call_api', return_value=mock_response):
            results = openai.detect('test@example.com', 'email')
            assert len(results) == 1
            assert results[0].pii_type == PIIType.EMAIL


# ===================================================================
# Schema-Level Detection
# ===================================================================

class TestSchemaDetection:
    """Test schema-level PII detection with mocked API responses."""

    @pytest.fixture
    def anthropic(self):
        return AnthropicDetector({'api_key': 'k', 'data_privacy_acknowledged': True})

    def test_schema_detection_finds_pii_fields(self, anthropic):
        mock_response = json.dumps([
            {'field': 'email', 'pii_type': 'EMAIL', 'confidence': 0.95, 'reasoning': 'email field'},
            {'field': 'ssn', 'pii_type': 'SSN', 'confidence': 0.9, 'reasoning': 'ssn field'},
        ])
        with patch.object(anthropic, '_call_api', return_value=mock_response):
            results = anthropic.detect_in_schema(
                ['email', 'ssn', 'amount', 'timestamp'],
                [{'email': 'test@example.com', 'ssn': '123-45-6789', 'amount': 100, 'timestamp': 123}]
            )
            assert len(results) == 2
            types = {r.pii_type for r in results}
            assert PIIType.EMAIL in types
            assert PIIType.SSN in types

    def test_schema_detection_no_pii(self, anthropic):
        mock_response = '[]'
        with patch.object(anthropic, '_call_api', return_value=mock_response):
            results = anthropic.detect_in_schema(
                ['amount', 'timestamp', 'status'],
            )
            assert len(results) == 0

    def test_schema_detection_ignores_unknown_fields(self, anthropic):
        mock_response = json.dumps([
            {'field': 'nonexistent', 'pii_type': 'EMAIL', 'confidence': 0.9},
        ])
        with patch.object(anthropic, '_call_api', return_value=mock_response):
            results = anthropic.detect_in_schema(['email', 'name'])
            assert len(results) == 0

    def test_schema_detection_handles_api_error(self, anthropic):
        with patch.object(anthropic, '_call_api', side_effect=Exception('timeout')):
            results = anthropic.detect_in_schema(['email', 'name'])
            assert len(results) == 0


# ===================================================================
# API Call Formatting
# ===================================================================

class TestAPICallFormat:
    """Test that each provider formats API calls correctly."""

    def test_openai_api_format(self):
        d = OpenAIDetector({'api_key': 'sk-test', 'data_privacy_acknowledged': True})
        with patch('src.pii.cloud_llm_detector.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    'choices': [{'message': {'content': '{"pii": false}'}}]
                },
                raise_for_status=lambda: None,
            )
            d.detect('test', 'field')
            call_kwargs = mock_post.call_args
            assert 'Bearer sk-test' in str(call_kwargs)
            assert 'chat/completions' in call_kwargs[0][0]

    def test_anthropic_api_format(self):
        d = AnthropicDetector({'api_key': 'sk-ant-test', 'data_privacy_acknowledged': True})
        with patch('src.pii.cloud_llm_detector.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    'content': [{'type': 'text', 'text': '{"pii": false}'}]
                },
                raise_for_status=lambda: None,
            )
            d.detect('test', 'field')
            call_kwargs = mock_post.call_args
            assert 'x-api-key' in str(call_kwargs)
            assert 'anthropic-version' in str(call_kwargs)
            assert 'api.anthropic.com' in call_kwargs[0][0]

    def test_gemini_api_format(self):
        d = GeminiDetector({'api_key': 'gem-test', 'data_privacy_acknowledged': True})
        with patch('src.pii.cloud_llm_detector.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    'candidates': [{'content': {'parts': [{'text': '{"pii": false}'}]}}]
                },
                raise_for_status=lambda: None,
            )
            d.detect('test', 'field')
            call_kwargs = mock_post.call_args
            assert 'generativelanguage.googleapis.com' in call_kwargs[0][0]
            assert 'key' in str(call_kwargs)


# ===================================================================
# Type Mapping
# ===================================================================

class TestTypeMapping:
    """Test the LLM type mapping dictionary."""

    @pytest.mark.parametrize("llm_type,expected", [
        ('ssn', PIIType.SSN),
        ('email', PIIType.EMAIL),
        ('phone', PIIType.PHONE_NUMBER),
        ('phone_number', PIIType.PHONE_NUMBER),
        ('address', PIIType.ADDRESS),
        ('credit_card', PIIType.CREDIT_CARD),
        ('name', PIIType.NAME),
        ('date_of_birth', PIIType.DATE_OF_BIRTH),
        ('passport', PIIType.PASSPORT),
        ('driver_license', PIIType.DRIVER_LICENSE),
        ('ip_address', PIIType.IP_ADDRESS),
        ('bank_account', PIIType.BANK_ACCOUNT),
        ('iban', PIIType.IBAN),
        ('swift_code', PIIType.SWIFT_CODE),
    ])
    def test_mapping(self, llm_type, expected):
        assert LLM_TYPE_MAPPING[llm_type] == expected


# ===================================================================
# Factory Registration
# ===================================================================

class TestFactoryRegistration:
    """Test providers are registered in the factory."""

    def test_openai_registered(self):
        from src.pii.factory import PIIDetectorFactory
        providers = PIIDetectorFactory.get_available_providers()
        assert 'openai' in providers
        assert 'chatgpt' in providers

    def test_anthropic_registered(self):
        from src.pii.factory import PIIDetectorFactory
        providers = PIIDetectorFactory.get_available_providers()
        assert 'anthropic' in providers
        assert 'claude' in providers

    def test_gemini_registered(self):
        from src.pii.factory import PIIDetectorFactory
        providers = PIIDetectorFactory.get_available_providers()
        assert 'gemini' in providers
