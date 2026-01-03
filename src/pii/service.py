"""Shared PII detection service for use across components."""

import logging
from typing import Dict, Any, List, Optional
from .detector import PIIDetector
from .types import PIIDetection

logger = logging.getLogger(__name__)


class PIIDetectionService:
    """
    Shared PII detection service that can be used by both:
    - Batch classification solution
    - Real-time streaming components
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize PII detection service.
        
        Args:
            config: PII detection configuration dictionary
        """
        self.config = config
        self.detector = PIIDetector(config)
        logger.info("PII Detection Service initialized")
    
    def detect(self, field_name: str, value: Any) -> List[PIIDetection]:
        """
        Detect PII in a field value.
        
        Args:
            field_name: Field name (for context)
            value: Field value to check
        
        Returns:
            List of PII detections
        """
        return self.detector.detect_in_field(field_name, value)
    
    def detect_in_message(self, message: Dict[str, Any]) -> Dict[str, List[PIIDetection]]:
        """
        Detect PII in all fields of a message.
        
        Args:
            message: Message dictionary (flat or nested)
        
        Returns:
            Dictionary mapping field names to detections
        """
        return self.detector.detect_in_message(message)
    
    def is_high_risk_pii(self, detections: List[PIIDetection]) -> bool:
        """
        Check if detections contain high-risk PII types.
        
        Args:
            detections: List of PII detections
        
        Returns:
            True if high-risk PII detected
        """
        from .types import PIIType
        
        high_risk_types = {
            PIIType.SSN,
            PIIType.CREDIT_CARD,
            PIIType.PASSPORT,
            PIIType.DRIVER_LICENSE
        }
        
        return any(d.pii_type in high_risk_types for d in detections)
    
    def get_detection_summary(self, detections: List[PIIDetection]) -> Dict[str, Any]:
        """
        Get summary of detections.
        
        Args:
            detections: List of PII detections
        
        Returns:
            Summary dictionary
        """
        if not detections:
            return {
                'pii_detected': False,
                'pii_types': [],
                'max_confidence': 0.0,
                'high_risk': False
            }
        
        pii_types = [d.pii_type.value for d in detections]
        max_confidence = max(d.confidence for d in detections)
        high_risk = self.is_high_risk_pii(detections)
        
        return {
            'pii_detected': True,
            'pii_types': list(set(pii_types)),
            'max_confidence': max_confidence,
            'high_risk': high_risk,
            'detection_count': len(detections)
        }

