"""Presidio-based PII detection (optional advanced detection)."""

import logging
from typing import List, Optional, Dict, Any

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

from .base_detector import PIIDetectorBase
from .types import PIIType, PIIDetection

logger = logging.getLogger(__name__)


# Map Presidio entity types to our PIIType enum
PRESIDIO_TO_PII_TYPE = {
    'PERSON': PIIType.NAME,
    'EMAIL_ADDRESS': PIIType.EMAIL,
    'PHONE_NUMBER': PIIType.PHONE_NUMBER,
    'IP_ADDRESS': PIIType.IP_ADDRESS,
    'LOCATION': PIIType.ADDRESS,
    'CREDIT_CARD': PIIType.CREDIT_CARD,
    'SSN': PIIType.SSN,
    'US_DRIVER_LICENSE': PIIType.DRIVER_LICENSE,
    'US_PASSPORT': PIIType.PASSPORT,
    'DATE_TIME': PIIType.DATE_OF_BIRTH,
    # Additional mapped types
    'IBAN_CODE': PIIType.IBAN,
    'SWIFT_CODE': PIIType.SWIFT_CODE,
    'US_BANK_NUMBER': PIIType.BANK_ACCOUNT,
    'UK_NHS': PIIType.NATIONAL_INSURANCE_NUMBER,
    # Note: IT_FISCAL_CODE and other country-specific types not yet mapped
    # Can be added as needed
}


class PresidioDetector(PIIDetectorBase):
    """Presidio-based PII detector for advanced NLP-based detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Presidio detector.
        
        Args:
            config: Optional configuration
        """
        if not PRESIDIO_AVAILABLE:
            logger.warning(
                "Presidio is not installed. "
                "Install with: pip install presidio-analyzer && python -m spacy download en_core_web_lg"
            )
            self.analyzer = None
            return
        
        try:
            self.analyzer = AnalyzerEngine()
            logger.info("Presidio analyzer initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize Presidio analyzer: {e}")
            logger.warning("Make sure you have installed:")
            logger.warning("  1. pip install presidio-analyzer")
            logger.warning("  2. python -m spacy download en_core_web_lg")
            self.analyzer = None
    
    def is_available(self) -> bool:
        """Check if Presidio is available and initialized."""
        return PRESIDIO_AVAILABLE and self.analyzer is not None
    
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII using Presidio.
        
        Args:
            value: Value to check
            field_name: Optional field name (for context)
        
        Returns:
            List of PII detections
        """
        if not self.is_available() or not value or not isinstance(value, str):
            return []
        
        try:
            # Include field name as context for better detection
            # NOTE: Presidio's context enhancement is ONE-WAY (BOOST only):
            # - It increases confidence when positive context words are found (e.g., "phone", "call")
            # - It does NOT reduce confidence for negative context (e.g., "time:", "timestamp:")
            # - It does NOT understand field names as negative context indicators
            # Therefore, we filter false positives in PatternDetector and conflict resolution instead
            
            # For structured data (like JSON fields), prepend field name as context
            # This helps Presidio when field name matches PII type (e.g., "phone: 123-456-7890")
            if field_name and len(field_name) > 0:
                # Create context-aware text: "field_name: value"
                text_with_context = f"{field_name}: {value}"
            else:
                text_with_context = value
            
            # Analyze text with Presidio
            results = self.analyzer.analyze(
                text=text_with_context,
                language='en'
            )
            
            detections = []
            for result in results:
                # Map Presidio entity to our PIIType
                pii_type = PRESIDIO_TO_PII_TYPE.get(result.entity_type)
                if pii_type:
                    # Extract the detected value from the original text_with_context
                    detected_text = text_with_context[result.start:result.end]
                    
                    # If context was added, the detected text might include the field name
                    # Extract just the value part (the part that matches the original value)
                    if field_name and detected_text.startswith(field_name + ":"):
                        # Remove field name prefix if present
                        detected_value = detected_text.split(":", 1)[1].strip()
                    else:
                        detected_value = detected_text
                    
                    # Only add if the detected value matches our original value
                    # (to avoid false matches from the field name itself)
                    if detected_value == value or value in detected_text:
                        detections.append(PIIDetection(
                            pii_type=pii_type,
                            confidence=result.score,
                            value=detected_value if detected_value == value else value,
                            pattern_matched=detected_value,
                            field_name=field_name
                        ))
            
            return detections
        
        except Exception as e:
            logger.warning(f"Presidio detection error: {e}")
            return []
    
    def get_supported_entities(self) -> List[str]:
        """
        Get list of entities Presidio can detect.
        
        Returns:
            List of entity type names
        """
        if not self.is_available():
            return []
        
        # Presidio analyzer has a registry of recognizers
        try:
            recognizers = self.analyzer.registry.get_recognizers()
            entities = set()
            for recognizer in recognizers:
                entities.update(recognizer.supported_entities)
            return sorted(list(entities))
        except Exception:
            return [
                'PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'IP_ADDRESS',
                'LOCATION', 'DATE_TIME', 'CREDIT_CARD', 'SSN',
                'US_DRIVER_LICENSE', 'US_PASSPORT', 'IBAN_CODE', 'SWIFT_CODE',
                # ... and many more international types
            ]

