"""Azure Text Analytics-based PII detection."""

import logging
from typing import List, Optional, Dict, Any

try:
    from azure.core.credentials import AzureKeyCredential
    from azure.ai.textanalytics import TextAnalyticsClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from .base_detector import PIIDetectorBase
from .types import PIIType, PIIDetection

logger = logging.getLogger(__name__)


# Map Azure entity types to our PIIType enum
AZURE_TO_PII_TYPE = {
    'USSocialSecurityNumber': PIIType.SSN,
    'Email': PIIType.EMAIL,
    'PhoneNumber': PIIType.PHONE_NUMBER,
    'IPAddress': PIIType.IP_ADDRESS,
    'Address': PIIType.ADDRESS,
    'CreditCardNumber': PIIType.CREDIT_CARD,
    'Date': PIIType.DATE_OF_BIRTH,
    'Person': PIIType.NAME,
    'USDriversLicenseNumber': PIIType.DRIVER_LICENSE,
    'PassportNumber': PIIType.PASSPORT,
    # Additional types (Azure may use different names - adjust as needed)
    'BankAccountNumber': PIIType.BANK_ACCOUNT,
    'IBAN': PIIType.IBAN,
    'SWIFTCode': PIIType.SWIFT_CODE,
    'ITIN': PIIType.ITIN,
    'UKNationalInsuranceNumber': PIIType.NATIONAL_INSURANCE_NUMBER,
    'Username': PIIType.USERNAME,
    'Password': PIIType.PASSWORD,
    'MACAddress': PIIType.MAC_ADDRESS,
}


class AzureTextAnalyticsDetector(PIIDetectorBase):
    """Azure Text Analytics-based PII detector."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Azure Text Analytics detector.
        
        Args:
            config: Configuration dictionary with Azure settings:
                - endpoint: Azure Text Analytics endpoint URL (required)
                - api_key: Azure API key (required)
                - language: Language code (default: 'en')
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "Azure Text Analytics library is not installed. "
                "Install with: pip install azure-ai-textanalytics"
            )
        
        self.config = config or {}
        self.endpoint = self.config.get('endpoint')
        self.api_key = self.config.get('api_key')
        
        if not self.endpoint or not self.api_key:
            raise ValueError(
                "Azure endpoint and api_key are required in configuration. "
                "Set 'endpoint' and 'api_key' in pii_detection.providers.azure"
            )
        
        self.language = self.config.get('language', 'en')
        
        # Initialize Azure client
        try:
            credential = AzureKeyCredential(self.api_key)
            self.client = TextAnalyticsClient(
                endpoint=self.endpoint,
                credential=credential
            )
            logger.info("Azure Text Analytics detector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Azure Text Analytics: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if Azure Text Analytics is available and initialized."""
        return AZURE_AVAILABLE and self.client is not None
    
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII using Azure Text Analytics.
        
        Args:
            value: Value to check
            field_name: Optional field name (for context)
        
        Returns:
            List of PII detections
        """
        if not self.is_available() or not value or not isinstance(value, str):
            return []
        
        try:
            # Azure PII detection
            documents = [value]
            response = self.client.recognize_pii_entities(
                documents=documents,
                language=self.language
            )
            
            detections = []
            for doc_result in response:
                if doc_result.is_error:
                    logger.warning(f"Azure PII detection error: {doc_result.error}")
                    continue
                
                for entity in doc_result.entities:
                    # Map Azure entity type to our PIIType
                    azure_type = entity.category
                    pii_type = AZURE_TO_PII_TYPE.get(azure_type)
                    
                    if pii_type:
                        # Get detected text
                        detected_text = entity.text
                        
                        # Get confidence score
                        confidence = entity.confidence_score if hasattr(entity, 'confidence_score') else 0.5
                        
                        detections.append(PIIDetection(
                            pii_type=pii_type,
                            confidence=confidence,
                            value=detected_text,
                            pattern_matched=detected_text,
                            field_name=field_name
                        ))
            
            return detections
        
        except Exception as e:
            logger.warning(f"Azure Text Analytics detection error: {e}")
            return []
    
    def get_supported_entities(self) -> List[str]:
        """
        Get list of entities Azure Text Analytics can detect.
        
        Returns:
            List of entity type names
        """
        if not self.is_available():
            return []
        
        return list(AZURE_TO_PII_TYPE.keys())

