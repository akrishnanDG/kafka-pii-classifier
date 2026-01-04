"""Ollama-based PII detector using local LLMs."""

import logging
import json
from typing import List, Dict, Any, Optional

from .base_detector import PIIDetectorBase
from .types import PIIDetection, PIIType

logger = logging.getLogger(__name__)

# Mapping of LLM response types to our PIIType enum
LLM_TYPE_MAPPING = {
    'ssn': PIIType.SSN,
    'social_security': PIIType.SSN,
    'social security number': PIIType.SSN,
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


class OllamaDetector(PIIDetectorBase):
    """
    PII detector using Ollama for local LLM inference.
    
    This detector runs LLMs locally for privacy-preserving PII detection.
    No data is sent to external services.
    
    Requires Ollama to be installed and running:
        curl -fsSL https://ollama.com/install.sh | sh
        ollama serve
        ollama pull llama3.2
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Ollama detector.
        
        Args:
            config: Configuration dictionary with:
                - base_url: Ollama API URL (required, e.g., http://localhost:11434)
                - model: Model name (required, e.g., llama3.2)
                - timeout: Request timeout in seconds (default: 30)
                - temperature: Model temperature (default: 0.1)
        """
        self.config = config or {}
        self.base_url = self.config.get('base_url')
        self.model = self.config.get('model')
        
        if not self.base_url:
            raise ValueError("ollama requires 'base_url' in config (e.g., http://localhost:11434)")
        if not self.model:
            raise ValueError("ollama requires 'model' in config (e.g., llama3.2)")
        self.timeout = self.config.get('timeout', 30)
        self.temperature = self.config.get('temperature', 0.1)
        self._available = None
        
        logger.info(f"Ollama detector initialized (model: {self.model}, url: {self.base_url})")
    
    def get_name(self) -> str:
        """Return detector name."""
        return "ollama"
    
    def get_supported_entities(self) -> List[str]:
        """Return list of supported PII types."""
        return [pt.name for pt in PIIType]
    
    def is_available(self) -> bool:
        """Check if Ollama is available."""
        if self._available is not None:
            return self._available
        
        try:
            import requests
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            self._available = response.status_code == 200
            
            if self._available:
                # Check if the specified model is available
                data = response.json()
                models = [m.get('name', '').split(':')[0] for m in data.get('models', [])]
                if self.model.split(':')[0] not in models:
                    logger.warning(
                        f"Model '{self.model}' not found in Ollama. "
                        f"Available models: {models}. "
                        f"Run: ollama pull {self.model}"
                    )
                    self._available = False
            
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            self._available = False
        
        return self._available
    
    def detect(self, value: str, field_name: str = "") -> List[PIIDetection]:
        """
        Detect PII using Ollama LLM.
        
        Args:
            value: The value to check for PII
            field_name: Optional field name for context
        
        Returns:
            List of PII detections
        """
        if not self.is_available():
            return []
        
        if not value or not isinstance(value, str):
            return []
        
        # Skip very short or very long values
        if len(value) < 3 or len(value) > 1000:
            return []
        
        try:
            import requests
            
            # Build prompt
            prompt = self._build_prompt(value, field_name)
            
            # Call Ollama API
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": 200  # Limit response length
                    }
                },
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.debug(f"Ollama API error: {response.status_code}")
                return []
            
            result = response.json()
            llm_response = result.get('response', '')
            
            # Parse LLM response
            detections = self._parse_response(llm_response, value, field_name)
            return detections
            
        except Exception as e:
            logger.debug(f"Ollama detection error: {e}")
            return []
    
    def _build_prompt(self, value: str, field_name: str) -> str:
        """Build the prompt for PII detection."""
        context = f" (field: {field_name})" if field_name else ""
        
        return f"""Analyze this value for PII (Personally Identifiable Information){context}.

Value: "{value}"

If this contains PII, respond with JSON: {{"pii": true, "type": "TYPE", "confidence": 0.0-1.0}}
Where TYPE is one of: ssn, email, phone, address, credit_card, name, date_of_birth, passport, driver_license, ip_address, bank_account, iban, swift_code

If no PII, respond: {{"pii": false}}

Respond with only the JSON, no explanation."""
    
    def _parse_response(
        self, 
        response: str, 
        value: str, 
        field_name: str
    ) -> List[PIIDetection]:
        """Parse LLM response into PII detections."""
        detections = []
        
        try:
            # Try to extract JSON from response
            response = response.strip()
            
            # Handle markdown code blocks
            if '```' in response:
                # Extract content between code blocks
                parts = response.split('```')
                for part in parts:
                    if part.strip().startswith('json'):
                        response = part.strip()[4:].strip()
                        break
                    elif part.strip().startswith('{'):
                        response = part.strip()
                        break
            
            # Find JSON object in response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                data = json.loads(json_str)
                
                if data.get('pii', False):
                    pii_type_str = data.get('type', '').lower().replace(' ', '_')
                    confidence = float(data.get('confidence', 0.8))
                    
                    # Map to our PIIType
                    pii_type = LLM_TYPE_MAPPING.get(pii_type_str)
                    
                    if pii_type:
                        detections.append(PIIDetection(
                            pii_type=pii_type,
                            value=value,
                            pattern_matched="ollama",
                            field_name=field_name,
                            confidence=min(1.0, max(0.0, confidence))
                        ))
                        
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse Ollama response as JSON: {response[:100]}")
        except Exception as e:
            logger.debug(f"Error parsing Ollama response: {e}")
        
        return detections

