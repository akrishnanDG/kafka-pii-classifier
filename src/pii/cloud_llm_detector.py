"""
Cloud LLM-based PII detectors for OpenAI, Anthropic, and Google Gemini.

These detectors send data to external cloud APIs for PII analysis.
Users MUST ensure compliance with applicable data protection regulations
(GDPR, CCPA, HIPAA, etc.) before enabling these providers.

No additional SDK dependencies required — uses requests (already a dependency).
"""

import json
import logging
from abc import abstractmethod
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from .base_detector import PIIDetectorBase
from .types import PIIDetection, PIIType

logger = logging.getLogger(__name__)

# Shared type mapping for LLM responses -> PIIType enum
LLM_TYPE_MAPPING = {
    'ssn': PIIType.SSN,
    'social_security': PIIType.SSN,
    'social_security_number': PIIType.SSN,
    'email': PIIType.EMAIL,
    'email_address': PIIType.EMAIL,
    'phone': PIIType.PHONE_NUMBER,
    'phone_number': PIIType.PHONE_NUMBER,
    'telephone': PIIType.PHONE_NUMBER,
    'address': PIIType.ADDRESS,
    'street_address': PIIType.ADDRESS,
    'credit_card': PIIType.CREDIT_CARD,
    'credit card': PIIType.CREDIT_CARD,
    'card_number': PIIType.CREDIT_CARD,
    'name': PIIType.NAME,
    'person_name': PIIType.NAME,
    'full_name': PIIType.NAME,
    'date_of_birth': PIIType.DATE_OF_BIRTH,
    'dob': PIIType.DATE_OF_BIRTH,
    'birthday': PIIType.DATE_OF_BIRTH,
    'passport': PIIType.PASSPORT,
    'passport_number': PIIType.PASSPORT,
    'driver_license': PIIType.DRIVER_LICENSE,
    'drivers_license': PIIType.DRIVER_LICENSE,
    'license_number': PIIType.DRIVER_LICENSE,
    'ip_address': PIIType.IP_ADDRESS,
    'ip': PIIType.IP_ADDRESS,
    'bank_account': PIIType.BANK_ACCOUNT,
    'account_number': PIIType.BANK_ACCOUNT,
    'iban': PIIType.IBAN,
    'swift': PIIType.SWIFT_CODE,
    'swift_code': PIIType.SWIFT_CODE,
}

_GDPR_WARNING = (
    "[DATA PRIVACY] Provider '{name}' sends data to external API ({endpoint}). "
    "Ensure this complies with your data protection obligations "
    "(GDPR, CCPA, HIPAA, etc.). PII field values and schema names will be "
    "transmitted to the provider. "
    "Set 'data_privacy_acknowledged: true' in provider config to suppress this warning."
)


class CloudLLMDetector(PIIDetectorBase):
    """
    Base class for cloud LLM PII detectors.

    Handles shared prompt building, response parsing, and GDPR warnings.
    Subclasses only need to implement _call_api() and provider-specific init.
    """

    # Subclasses must set these
    PROVIDER_NAME: str = "cloud_llm"
    DEFAULT_ENDPOINT: str = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.api_key = self.config.get('api_key')
        self.model = self.config.get('model')
        self.timeout = self.config.get('timeout', 60)
        self.temperature = self.config.get('temperature', 0.1)
        self._available: Optional[bool] = None

        if not self.api_key:
            raise ValueError(
                f"{self.PROVIDER_NAME} requires 'api_key' in config. "
                f"Set it directly or use env var substitution: "
                f"api_key: \"${{{self.PROVIDER_NAME.upper()}_API_KEY}}\""
            )

        # GDPR / data privacy warning
        if not self.config.get('data_privacy_acknowledged', False):
            logger.warning(_GDPR_WARNING.format(
                name=self.PROVIDER_NAME,
                endpoint=self.DEFAULT_ENDPOINT,
            ))

        logger.info(
            f"{self.PROVIDER_NAME} detector initialized "
            f"(model: {self.model})"
        )

    @staticmethod
    def _validate_base_url(url: str):
        """Validate base_url to prevent SSRF attacks."""
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(
                f"base_url must use http or https scheme, got: {parsed.scheme}"
            )
        hostname = parsed.hostname or ''
        blocked = [
            '169.254.169.254', 'metadata.google.internal', '169.254.170.2'
        ]
        if hostname in blocked:
            raise ValueError(
                f"base_url hostname is blocked for security: {hostname}"
            )

    # ------------------------------------------------------------------
    # Abstract method — subclasses implement the actual API call
    # ------------------------------------------------------------------

    @abstractmethod
    def _call_api(self, prompt: str) -> str:
        """Call the provider's API and return the text response.

        Args:
            prompt: The full prompt to send

        Returns:
            The text response from the LLM
        """

    # ------------------------------------------------------------------
    # PIIDetectorBase interface
    # ------------------------------------------------------------------

    def get_name(self) -> str:
        return self.PROVIDER_NAME

    def get_supported_entities(self) -> List[str]:
        return [pt.name for pt in PIIType]

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        # Cloud APIs are available if we have an API key
        self._available = bool(self.api_key)
        return self._available

    def detect(self, value: str, field_name: str = "") -> List[PIIDetection]:
        """Detect PII in a single field value."""
        if not self.is_available():
            return []
        if not value or not isinstance(value, str):
            return []
        if len(value) < 3 or len(value) > 1000:
            return []

        try:
            prompt = self._build_field_prompt(value, field_name)
            response = self._call_api(prompt)
            return self._parse_field_response(response, value, field_name)
        except Exception as e:
            logger.debug(f"{self.PROVIDER_NAME} detection error: {e}")
            return []

    def detect_in_schema(
        self,
        field_names: List[str],
        sample_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[PIIDetection]:
        """Detect PII at schema level (1 API call for all fields)."""
        if not self.is_available() or not field_names:
            return []

        try:
            # Build sample values per field
            sample_values: Dict[str, List[str]] = {}
            if sample_data:
                for field in field_names:
                    values = []
                    for record in sample_data[:10]:
                        if field in record and record[field]:
                            val = str(record[field])
                            if val and len(val) < 200:
                                values.append(val)
                    if values:
                        sample_values[field] = values[:5]

            prompt = self._build_schema_prompt(field_names, sample_values)
            response = self._call_api(prompt)
            return self._parse_schema_response(response, field_names)
        except Exception as e:
            logger.error(f"{self.PROVIDER_NAME} schema analysis failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_field_prompt(self, value: str, field_name: str) -> str:
        context = f" (field: {field_name})" if field_name else ""
        return (
            f"Analyze this value for PII (Personally Identifiable Information)"
            f"{context}.\n\n"
            f'Value: "{value}"\n\n'
            f'If this contains PII, respond with JSON: '
            f'{{"pii": true, "type": "TYPE", "confidence": 0.0-1.0}}\n'
            f"Where TYPE is one of: ssn, email, phone, address, credit_card, "
            f"name, date_of_birth, passport, driver_license, ip_address, "
            f"bank_account, iban, swift_code\n\n"
            f'If no PII, respond: {{"pii": false}}\n\n'
            f"Respond with only the JSON, no explanation."
        )

    def _build_schema_prompt(
        self,
        field_names: List[str],
        sample_values: Optional[Dict[str, List[str]]] = None
    ) -> str:
        fields_info = []
        for name in field_names:
            if sample_values and name in sample_values:
                samples = sample_values[name][:3]
                fields_info.append(f"- {name}: {samples}")
            else:
                fields_info.append(f"- {name}")

        fields_str = "\n".join(fields_info)
        pii_types = (
            "SSN, EMAIL, PHONE_NUMBER, ADDRESS, CREDIT_CARD, NAME, "
            "DATE_OF_BIRTH, PASSPORT, DRIVER_LICENSE, IP_ADDRESS, "
            "BANK_ACCOUNT, IBAN, SWIFT_CODE"
        )

        return (
            f"You are a PII (Personally Identifiable Information) detection "
            f"expert.\n\n"
            f"Analyze these database/message schema fields and identify which "
            f"ones likely contain PII:\n\n"
            f"FIELDS:\n{fields_str}\n\n"
            f"PII TYPES TO CHECK: {pii_types}\n\n"
            f"For each field that might contain PII, respond with a JSON "
            f"array:\n"
            f'[\n  {{"field": "field_name", "pii_type": "TYPE", '
            f'"confidence": 0.0-1.0, "reasoning": "brief reason"}},\n  ...\n'
            f"]\n\n"
            f"Rules:\n"
            f"- Only include fields that likely contain PII\n"
            f"- Consider field names like \"email\", \"ssn\", \"phone\", "
            f"\"address\" as strong indicators\n"
            f"- Consider patterns in sample values if provided\n"
            f"- Be conservative - only flag clear PII indicators\n"
            f"- If no PII fields found, return: []\n\n"
            f"Respond with ONLY the JSON array, no explanation."
        )

    # ------------------------------------------------------------------
    # Response parsers
    # ------------------------------------------------------------------

    def _parse_field_response(
        self, response: str, value: str, field_name: str
    ) -> List[PIIDetection]:
        """Parse single-field JSON response from LLM."""
        detections = []
        try:
            cleaned = self._extract_json(response)
            start = cleaned.find('{')
            end = cleaned.rfind('}') + 1
            if start >= 0 and end > start:
                data = json.loads(cleaned[start:end])
                if data.get('pii', False):
                    pii_type_str = (
                        data.get('type', '').lower().replace(' ', '_')
                    )
                    confidence = float(data.get('confidence', 0.8))
                    pii_type = LLM_TYPE_MAPPING.get(pii_type_str)
                    if pii_type:
                        detections.append(PIIDetection(
                            pii_type=pii_type,
                            value=value,
                            pattern_matched=self.PROVIDER_NAME,
                            field_name=field_name,
                            confidence=min(1.0, max(0.0, confidence))
                        ))
        except (json.JSONDecodeError, ValueError):
            logger.debug(
                f"Failed to parse {self.PROVIDER_NAME} response: "
                f"{response[:100]}"
            )
        return detections

    def _parse_schema_response(
        self, response: str, field_names: List[str]
    ) -> List[PIIDetection]:
        """Parse schema-level JSON array response from LLM."""
        detections = []
        try:
            cleaned = self._extract_json(response)
            start = cleaned.find('[')
            end = cleaned.rfind(']') + 1
            if start >= 0 and end > start:
                data = json.loads(cleaned[start:end])
                for item in data:
                    field = item.get('field', '')
                    pii_type_str = item.get('pii_type', '').upper()
                    confidence = float(item.get('confidence', 0.8))

                    pii_type = None
                    for pt in PIIType:
                        if pt.name == pii_type_str or pt.value == pii_type_str:
                            pii_type = pt
                            break
                    # Also try the lowercase mapping
                    if pii_type is None:
                        pii_type = LLM_TYPE_MAPPING.get(
                            pii_type_str.lower().replace(' ', '_')
                        )

                    if field in field_names and pii_type:
                        detections.append(PIIDetection(
                            pii_type=pii_type,
                            value="[schema-based detection]",
                            pattern_matched=f"{self.PROVIDER_NAME}:schema",
                            field_name=field,
                            confidence=min(1.0, max(0.0, confidence))
                        ))

        except (json.JSONDecodeError, ValueError):
            logger.debug(
                f"Failed to parse {self.PROVIDER_NAME} schema response: "
                f"{response[:200]}"
            )
        return detections

    @staticmethod
    def _extract_json(response: str) -> str:
        """Extract JSON from a response that may contain markdown blocks."""
        response = response.strip()
        if '```' in response:
            parts = response.split('```')
            for part in parts:
                stripped = part.strip()
                if stripped.startswith('json'):
                    return stripped[4:].strip()
                elif stripped.startswith('[') or stripped.startswith('{'):
                    return stripped
        return response


# ======================================================================
# OpenAI / ChatGPT
# ======================================================================

class OpenAIDetector(CloudLLMDetector):
    """PII detector using OpenAI API (GPT-4, GPT-4o, etc.)."""

    PROVIDER_NAME = "openai"
    DEFAULT_ENDPOINT = "api.openai.com"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        config.setdefault('model', 'gpt-4o-mini')
        self.base_url = config.get(
            'base_url', 'https://api.openai.com/v1'
        ).rstrip('/')
        if config.get('base_url'):
            self._validate_base_url(self.base_url)
        super().__init__(config)

    def _call_api(self, prompt: str) -> str:
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
            },
            json={
                'model': self.model,
                'messages': [
                    {'role': 'system', 'content': 'You are a PII detection expert. Respond only with JSON.'},
                    {'role': 'user', 'content': prompt},
                ],
                'temperature': self.temperature,
                'max_tokens': 500,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']


# ======================================================================
# Anthropic / Claude
# ======================================================================

class AnthropicDetector(CloudLLMDetector):
    """PII detector using Anthropic API (Claude)."""

    PROVIDER_NAME = "anthropic"
    DEFAULT_ENDPOINT = "api.anthropic.com"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        config.setdefault('model', 'claude-sonnet-4-20250514')
        super().__init__(config)

    def _call_api(self, prompt: str) -> str:
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'x-api-key': self.api_key,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json',
            },
            json={
                'model': self.model,
                'max_tokens': 500,
                'messages': [
                    {'role': 'user', 'content': prompt},
                ],
                'system': 'You are a PII detection expert. Respond only with JSON.',
                'temperature': self.temperature,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        content = response.json()['content']
        # Anthropic returns a list of content blocks
        return ''.join(
            block['text'] for block in content if block['type'] == 'text'
        )


# ======================================================================
# Google Gemini
# ======================================================================

class GeminiDetector(CloudLLMDetector):
    """PII detector using Google Gemini API."""

    PROVIDER_NAME = "gemini"
    DEFAULT_ENDPOINT = "generativelanguage.googleapis.com"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        config.setdefault('model', 'gemini-2.0-flash')
        super().__init__(config)

    def _call_api(self, prompt: str) -> str:
        model = self.model
        response = requests.post(
            f'https://generativelanguage.googleapis.com/v1beta/'
            f'models/{model}:generateContent',
            params={'key': self.api_key},
            headers={'Content-Type': 'application/json'},
            json={
                'contents': [
                    {'parts': [{'text': prompt}]}
                ],
                'generationConfig': {
                    'temperature': self.temperature,
                    'maxOutputTokens': 500,
                },
                'systemInstruction': {
                    'parts': [{'text': 'You are a PII detection expert. Respond only with JSON.'}]
                },
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        candidates = response.json().get('candidates', [])
        if candidates:
            parts = candidates[0].get('content', {}).get('parts', [])
            return ''.join(p.get('text', '') for p in parts)
        return ''
