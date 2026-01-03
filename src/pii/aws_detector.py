"""AWS Comprehend-based PII detection."""

import logging
from typing import List, Optional, Dict, Any

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

from .base_detector import PIIDetectorBase
from .types import PIIType, PIIDetection

logger = logging.getLogger(__name__)


# Map AWS Comprehend entity types to our PIIType enum
AWS_TO_PII_TYPE = {
    'SSN': PIIType.SSN,
    'EMAIL': PIIType.EMAIL,
    'PHONE': PIIType.PHONE_NUMBER,
    'IP_ADDRESS': PIIType.IP_ADDRESS,
    'ADDRESS': PIIType.ADDRESS,
    'CREDIT_DEBIT_NUMBER': PIIType.CREDIT_CARD,
    'DATE_TIME': PIIType.DATE_OF_BIRTH,
    'PERSON': PIIType.NAME,
    'DRIVER_ID': PIIType.DRIVER_LICENSE,
    'PASSPORT_NUMBER': PIIType.PASSPORT,
    # Additional types
    'BANK_ACCOUNT_NUMBER': PIIType.BANK_ACCOUNT,
    'IBAN': PIIType.IBAN,
    'SWIFT_CODE': PIIType.SWIFT_CODE,
    'AWS_ACCESS_KEY': PIIType.AWS_ACCESS_KEY,
    'AWS_SECRET_KEY': PIIType.AWS_SECRET_KEY,
    'ITIN': PIIType.ITIN,
    'UK_NATIONAL_INSURANCE_NUMBER': PIIType.NATIONAL_INSURANCE_NUMBER,
    'USERNAME': PIIType.USERNAME,
    'PASSWORD': PIIType.PASSWORD,
    'MAC_ADDRESS': PIIType.MAC_ADDRESS,
}


class AWSComprehendDetector(PIIDetectorBase):
    """AWS Comprehend-based PII detector."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AWS Comprehend detector.
        
        Args:
            config: Configuration dictionary with AWS settings:
                - region_name: AWS region (default: 'us-east-1')
                - aws_access_key_id: AWS access key (optional, can use IAM role)
                - aws_secret_access_key: AWS secret key (optional, can use IAM role)
                - language_code: Language code (default: 'en')
        """
        if not AWS_AVAILABLE:
            raise ImportError(
                "AWS SDK (boto3) is not installed. "
                "Install with: pip install boto3"
            )
        
        self.config = config or {}
        self.region_name = self.config.get('region_name', 'us-east-1')
        self.language_code = self.config.get('language_code', 'en')
        
        # Initialize Comprehend client
        try:
            client_config = {
                'region_name': self.region_name
            }
            
            # Add credentials if provided
            if 'aws_access_key_id' in self.config:
                client_config['aws_access_key_id'] = self.config['aws_access_key_id']
            if 'aws_secret_access_key' in self.config:
                client_config['aws_secret_access_key'] = self.config['aws_secret_access_key']
            
            self.client = boto3.client('comprehend', **client_config)
            logger.info(f"AWS Comprehend detector initialized (region: {self.region_name})")
        except Exception as e:
            logger.error(f"Failed to initialize AWS Comprehend: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if AWS Comprehend is available and initialized."""
        return AWS_AVAILABLE and self.client is not None
    
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII using AWS Comprehend.
        
        Args:
            value: Value to check
            field_name: Optional field name (for context)
        
        Returns:
            List of PII detections
        """
        if not self.is_available() or not value or not isinstance(value, str):
            return []
        
        try:
            # AWS Comprehend PII detection
            response = self.client.detect_pii_entities(
                Text=value,
                LanguageCode=self.language_code
            )
            
            detections = []
            for entity in response.get('Entities', []):
                # Map AWS entity type to our PIIType
                aws_type = entity.get('Type', '')
                pii_type = AWS_TO_PII_TYPE.get(aws_type)
                
                if pii_type:
                    # Extract detected text
                    start = entity.get('BeginOffset', 0)
                    end = entity.get('EndOffset', len(value))
                    detected_text = value[start:end]
                    
                    # Get confidence score
                    score = entity.get('Score', 0.0)
                    
                    detections.append(PIIDetection(
                        pii_type=pii_type,
                        confidence=score,
                        value=detected_text,
                        pattern_matched=detected_text,
                        field_name=field_name
                    ))
            
            return detections
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'TextSizeLimitExceededException':
                logger.warning(f"AWS Comprehend text size limit exceeded for field {field_name}")
            else:
                logger.warning(f"AWS Comprehend detection error: {e}")
            return []
        except BotoCoreError as e:
            logger.warning(f"AWS Comprehend service error: {e}")
            return []
        except Exception as e:
            logger.warning(f"AWS Comprehend detection error: {e}")
            return []
    
    def get_supported_entities(self) -> List[str]:
        """
        Get list of entities AWS Comprehend can detect.
        
        Returns:
            List of entity type names
        """
        if not self.is_available():
            return []
        
        return list(AWS_TO_PII_TYPE.keys())

