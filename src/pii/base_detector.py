"""Abstract base class for PII detection providers."""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from .types import PIIDetection


class PIIDetectorBase(ABC):
    """Abstract base class for PII detection providers."""
    
    @abstractmethod
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII in a value.
        
        Args:
            value: Value to check for PII
            field_name: Optional field name (for context hints)
        
        Returns:
            List of PII detections
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the detector is available and properly initialized.
        
        Returns:
            True if available, False otherwise
        """
        pass
    
    @abstractmethod
    def get_supported_entities(self) -> List[str]:
        """
        Get list of entity types this detector can identify.
        
        Returns:
            List of entity type names
        """
        pass
    
    def get_name(self) -> str:
        """
        Get the name of this detector provider.
        
        Returns:
            Provider name (e.g., "presidio", "aws", "gcp", "azure")
        """
        return self.__class__.__name__.lower().replace('detector', '')

