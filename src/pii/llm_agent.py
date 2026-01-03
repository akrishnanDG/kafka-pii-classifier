"""
LLM-powered PII Detection Agent.

This implements an intelligent agent pattern where the LLM:
1. Analyzes the schema/field names first (1 call)
2. Strategically samples suspicious fields
3. Makes classification decisions

Much more efficient than per-field prompting.
"""

import logging
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .base_detector import PIIDetectorBase
from .types import PIIDetection, PIIType

logger = logging.getLogger(__name__)


class AgentAction(Enum):
    """Actions the agent can take."""
    ANALYZE_SCHEMA = "analyze_schema"
    SAMPLE_FIELD = "sample_field"
    CLASSIFY_FIELD = "classify_field"
    FINISH = "finish"


@dataclass
class FieldAnalysis:
    """Result of analyzing a field."""
    field_name: str
    suspected_pii_type: Optional[PIIType]
    confidence: float
    reasoning: str
    needs_value_check: bool


class PIIDetectionAgent:
    """
    Intelligent LLM agent for PII detection.
    
    Instead of checking every field value individually, this agent:
    1. First analyzes the SCHEMA (field names) to identify likely PII fields
    2. Then spot-checks sample VALUES only for suspicious fields
    3. Makes final classification decisions
    
    This reduces LLM calls from O(messages × fields) to O(1) per topic.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the agent.
        
        Args:
            config: Configuration with:
                - base_url: Ollama API URL (default: http://localhost:11434)
                - model: Model name (default: llama3.2)
                - timeout: Request timeout (default: 60)
        """
        self.config = config or {}
        self.base_url = self.config.get('base_url', 'http://localhost:11434')
        self.model = self.config.get('model', 'llama3.2')
        self.timeout = self.config.get('timeout', 60)
        self._available = None
        
        # PII type mapping
        self.pii_types = [
            "SSN", "EMAIL", "PHONE_NUMBER", "ADDRESS", "CREDIT_CARD",
            "NAME", "DATE_OF_BIRTH", "PASSPORT", "DRIVER_LICENSE",
            "IP_ADDRESS", "BANK_ACCOUNT", "IBAN", "SWIFT_CODE"
        ]
        
        logger.info(f"PII Detection Agent initialized (model: {self.model})")
    
    def get_name(self) -> str:
        return "llm_agent"
    
    def is_available(self) -> bool:
        """Check if Ollama is available."""
        if self._available is not None:
            return self._available
        
        try:
            import requests
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            self._available = response.status_code == 200
        except Exception:
            self._available = False
        
        return self._available
    
    def analyze_schema(
        self, 
        field_names: List[str],
        sample_values: Optional[Dict[str, List[str]]] = None
    ) -> List[FieldAnalysis]:
        """
        Analyze schema field names to identify likely PII fields.
        
        This is the KEY optimization: Instead of checking every value,
        we first ask the LLM to analyze field names and identify which
        ones are likely to contain PII.
        
        Args:
            field_names: List of field names from the schema
            sample_values: Optional dict of field_name -> sample values
        
        Returns:
            List of FieldAnalysis with suspected PII types
        """
        if not self.is_available():
            return []
        
        # Build the prompt
        prompt = self._build_schema_analysis_prompt(field_names, sample_values)
        
        try:
            response = self._call_llm(prompt)
            analyses = self._parse_schema_analysis(response, field_names)
            return analyses
        except Exception as e:
            logger.error(f"Schema analysis failed: {e}")
            return []
    
    def _build_schema_analysis_prompt(
        self, 
        field_names: List[str],
        sample_values: Optional[Dict[str, List[str]]] = None
    ) -> str:
        """Build prompt for schema analysis."""
        
        fields_info = []
        for name in field_names:
            if sample_values and name in sample_values:
                samples = sample_values[name][:3]  # Max 3 samples
                fields_info.append(f"- {name}: {samples}")
            else:
                fields_info.append(f"- {name}")
        
        fields_str = "\n".join(fields_info)
        pii_types_str = ", ".join(self.pii_types)
        
        return f"""You are a PII (Personally Identifiable Information) detection expert.

Analyze these database/message schema fields and identify which ones likely contain PII:

FIELDS:
{fields_str}

PII TYPES TO CHECK: {pii_types_str}

For each field that might contain PII, respond with a JSON array:
[
  {{"field": "field_name", "pii_type": "TYPE", "confidence": 0.0-1.0, "reasoning": "brief reason"}},
  ...
]

Rules:
- Only include fields that likely contain PII
- Consider field names like "email", "ssn", "phone", "address" as strong indicators
- Consider patterns in sample values if provided
- Be conservative - only flag clear PII indicators
- If no PII fields found, return: []

Respond with ONLY the JSON array, no explanation."""

    def _build_value_verification_prompt(
        self,
        field_name: str,
        suspected_type: str,
        sample_values: List[str]
    ) -> str:
        """Build prompt for value verification."""
        samples_str = "\n".join([f"  - {v}" for v in sample_values[:5]])
        
        return f"""Verify if these values from field "{field_name}" contain {suspected_type} PII:

VALUES:
{samples_str}

Respond with JSON:
{{"confirmed": true/false, "confidence": 0.0-1.0, "reasoning": "brief reason"}}

Respond with ONLY the JSON, no explanation."""

    def _call_llm(self, prompt: str) -> str:
        """Call Ollama API."""
        import requests
        
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 500
                }
            },
            timeout=self.timeout
        )
        
        if response.status_code != 200:
            raise Exception(f"Ollama API error: {response.status_code}")
        
        return response.json().get('response', '')
    
    def _parse_schema_analysis(
        self, 
        response: str, 
        field_names: List[str]
    ) -> List[FieldAnalysis]:
        """Parse LLM response into FieldAnalysis objects."""
        analyses = []
        
        try:
            # Extract JSON from response
            response = response.strip()
            if '```' in response:
                parts = response.split('```')
                for part in parts:
                    if part.strip().startswith('json'):
                        response = part.strip()[4:].strip()
                        break
                    elif part.strip().startswith('['):
                        response = part.strip()
                        break
            
            start = response.find('[')
            end = response.rfind(']') + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                data = json.loads(json_str)
                
                for item in data:
                    field = item.get('field', '')
                    pii_type_str = item.get('pii_type', '').upper()
                    confidence = float(item.get('confidence', 0.8))
                    reasoning = item.get('reasoning', '')
                    
                    # Map to PIIType
                    pii_type = None
                    for pt in PIIType:
                        if pt.name == pii_type_str or pt.value == pii_type_str:
                            pii_type = pt
                            break
                    
                    if field in field_names:
                        analyses.append(FieldAnalysis(
                            field_name=field,
                            suspected_pii_type=pii_type,
                            confidence=min(1.0, max(0.0, confidence)),
                            reasoning=reasoning,
                            needs_value_check=confidence < 0.9  # High confidence = no need to check values
                        ))
                        
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse schema analysis: {response[:200]}")
        except Exception as e:
            logger.debug(f"Error parsing schema analysis: {e}")
        
        return analyses
    
    def verify_field_values(
        self,
        field_name: str,
        suspected_type: PIIType,
        sample_values: List[str]
    ) -> Tuple[bool, float]:
        """
        Verify if sample values actually contain the suspected PII type.
        
        Args:
            field_name: Name of the field
            suspected_type: Suspected PII type from schema analysis
            sample_values: Sample values to check
        
        Returns:
            Tuple of (confirmed, confidence)
        """
        if not self.is_available() or not sample_values:
            return False, 0.0
        
        prompt = self._build_value_verification_prompt(
            field_name, 
            suspected_type.name, 
            sample_values
        )
        
        try:
            response = self._call_llm(prompt)
            
            # Parse response
            response = response.strip()
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                confirmed = data.get('confirmed', False)
                confidence = float(data.get('confidence', 0.5))
                return confirmed, confidence
                
        except Exception as e:
            logger.debug(f"Value verification failed: {e}")
        
        return False, 0.0
    
    def detect_pii_in_schema(
        self,
        field_names: List[str],
        sample_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[PIIDetection]:
        """
        Main entry point: Detect PII in a schema using the agent approach.
        
        Args:
            field_names: List of field names
            sample_data: Optional list of sample records
        
        Returns:
            List of PII detections
        """
        detections = []
        
        # Step 1: Extract sample values per field (if available)
        sample_values = {}
        if sample_data:
            for field in field_names:
                values = []
                for record in sample_data[:10]:  # Max 10 samples
                    if field in record and record[field]:
                        val = str(record[field])
                        if val and len(val) < 200:  # Skip very long values
                            values.append(val)
                if values:
                    sample_values[field] = values[:5]  # Max 5 per field
        
        # Step 2: Analyze schema (1 LLM call)
        logger.info(f"Analyzing schema with {len(field_names)} fields...")
        analyses = self.analyze_schema(field_names, sample_values)
        
        if not analyses:
            logger.info("No PII fields detected in schema")
            return []
        
        logger.info(f"Found {len(analyses)} potential PII fields")
        
        # Step 3: Verify suspicious fields (optional, only for low-confidence)
        for analysis in analyses:
            if analysis.suspected_pii_type is None:
                continue
            
            # If high confidence from schema analysis, skip value verification
            if analysis.confidence >= 0.85 or not analysis.needs_value_check:
                detections.append(PIIDetection(
                    pii_type=analysis.suspected_pii_type,
                    value="[schema-based detection]",
                    pattern_matched="llm_agent:schema",
                    field_name=analysis.field_name,
                    confidence=analysis.confidence
                ))
                logger.info(
                    f"  ✓ {analysis.field_name}: {analysis.suspected_pii_type.name} "
                    f"(confidence: {analysis.confidence:.0%})"
                )
            else:
                # Need to verify with actual values
                field_samples = sample_values.get(analysis.field_name, [])
                if field_samples:
                    confirmed, conf = self.verify_field_values(
                        analysis.field_name,
                        analysis.suspected_pii_type,
                        field_samples
                    )
                    if confirmed and conf > 0.6:
                        detections.append(PIIDetection(
                            pii_type=analysis.suspected_pii_type,
                            value="[value-verified detection]",
                            pattern_matched="llm_agent:verified",
                            field_name=analysis.field_name,
                            confidence=conf
                        ))
                        logger.info(
                            f"  ✓ {analysis.field_name}: {analysis.suspected_pii_type.name} "
                            f"(verified, confidence: {conf:.0%})"
                        )
        
        return detections


class SchemaAwareLLMDetector(PIIDetectorBase):
    """
    Wrapper that makes the LLM agent compatible with the existing detector interface.
    
    This detector works at the SCHEMA level, not the field level.
    It should be called once per topic, not per field.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.agent = PIIDetectionAgent(config)
        self._schema_cache: Dict[str, List[PIIDetection]] = {}
    
    def get_name(self) -> str:
        return "llm_agent"
    
    def get_supported_entities(self) -> List[str]:
        """Return list of supported PII types."""
        return [pt.name for pt in PIIType]
    
    def is_available(self) -> bool:
        return self.agent.is_available()
    
    def detect(self, value: str, field_name: str = "") -> List[PIIDetection]:
        """
        Standard detect interface - but this is NOT the recommended way.
        
        For efficiency, use detect_in_schema() instead.
        This method exists for compatibility with the existing interface.
        """
        # For single field detection, fall back to basic approach
        if not self.is_available():
            return []
        
        # Check cache first
        cache_key = f"{field_name}:{hash(value)}"
        if cache_key in self._schema_cache:
            return self._schema_cache[cache_key]
        
        # This is inefficient - just checking one field
        # Better to use detect_in_schema()
        detections = self.agent.detect_pii_in_schema(
            field_names=[field_name],
            sample_data=[{field_name: value}] if value else None
        )
        
        self._schema_cache[cache_key] = detections
        return detections
    
    def detect_in_schema(
        self,
        field_names: List[str],
        sample_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[PIIDetection]:
        """
        Recommended method: Analyze entire schema at once.
        
        Args:
            field_names: All field names from the schema
            sample_data: Sample records from the topic
        
        Returns:
            List of PII detections for the entire schema
        """
        return self.agent.detect_pii_in_schema(field_names, sample_data)

