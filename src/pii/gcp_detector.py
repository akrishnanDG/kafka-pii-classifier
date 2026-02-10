"""Google Cloud DLP-based PII detection."""

import logging
from typing import List, Optional, Dict, Any

try:
    from google.cloud import dlp_v2
    from google.api_core import exceptions as gcp_exceptions
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from .base_detector import PIIDetectorBase
from .types import PIIType, PIIDetection

logger = logging.getLogger(__name__)


# Map GCP DLP info types to our PIIType enum
GCP_TO_PII_TYPE = {
    'US_SOCIAL_SECURITY_NUMBER': PIIType.SSN,
    'EMAIL_ADDRESS': PIIType.EMAIL,
    'PHONE_NUMBER': PIIType.PHONE_NUMBER,
    'IP_ADDRESS': PIIType.IP_ADDRESS,
    'STREET_ADDRESS': PIIType.ADDRESS,
    'CREDIT_CARD_NUMBER': PIIType.CREDIT_CARD,
    'DATE_OF_BIRTH': PIIType.DATE_OF_BIRTH,
    'PERSON_NAME': PIIType.NAME,
    'US_DRIVERS_LICENSE_NUMBER': PIIType.DRIVER_LICENSE,
    'PASSPORT': PIIType.PASSPORT,
    # Additional types
    'US_BANK_ACCOUNT_NUMBER': PIIType.BANK_ACCOUNT,
    'IBAN_CODE': PIIType.IBAN,
    'SWIFT_CODE': PIIType.SWIFT_CODE,
    'AWS_ACCESS_KEY_ID': PIIType.AWS_ACCESS_KEY,
    'AWS_SECRET_ACCESS_KEY': PIIType.AWS_SECRET_KEY,
    'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER': PIIType.ITIN,
    'UK_NATIONAL_INSURANCE_NUMBER': PIIType.NATIONAL_INSURANCE_NUMBER,
    'USERNAME': PIIType.USERNAME,
    'PASSWORD': PIIType.PASSWORD,
    'MAC_ADDRESS_LOCAL': PIIType.MAC_ADDRESS,
}


class GCPDLPDetector(PIIDetectorBase):
    """Google Cloud DLP-based PII detector."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize GCP DLP detector.
        
        Args:
            config: Configuration dictionary with GCP settings:
                - project_id: GCP project ID (required)
                - credentials_path: Path to service account JSON (optional)
                - location: Location/region (default: 'global')
        """
        if not GCP_AVAILABLE:
            raise ImportError(
                "Google Cloud DLP library is not installed. "
                "Install with: pip install google-cloud-dlp"
            )
        
        self.config = config or {}
        self.project_id = self.config.get('project_id')
        
        if not self.project_id:
            raise ValueError("GCP project_id is required in configuration")
        
        self.location = self.config.get('location', 'global')
        
        # Initialize DLP client
        try:
            if 'credentials_path' in self.config:
                from google.oauth2 import service_account
                credentials = service_account.Credentials.from_service_account_file(
                    self.config['credentials_path']
                )
                self.client = dlp_v2.DlpServiceClient(credentials=credentials)
            else:
                self.client = dlp_v2.DlpServiceClient()
            logger.info(f"GCP DLP detector initialized (project: {self.project_id})")
        except Exception as e:
            logger.error(f"Failed to initialize GCP DLP: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if GCP DLP is available and initialized."""
        return GCP_AVAILABLE and self.client is not None and self.project_id is not None
    
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII using GCP DLP.
        
        Args:
            value: Value to check
            field_name: Optional field name (for context)
        
        Returns:
            List of PII detections
        """
        if not self.is_available() or not value or not isinstance(value, str):
            return []
        
        try:
            # Prepare the item to inspect
            item = {"value": value}
            
            # Configure inspection request
            parent = f"projects/{self.project_id}/locations/{self.location}"
            
            # Inspect configuration - detect all info types
            inspect_config = {
                "info_types": [{"name": info_type} for info_type in GCP_TO_PII_TYPE.keys()],
                "min_likelihood": dlp_v2.Likelihood.POSSIBLE,
                "include_quote": True,
            }
            
            # Run inspection
            response = self.client.inspect_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "item": item,
                }
            )
            
            detections = []
            for finding in response.result.findings:
                # Map GCP info type to our PIIType
                info_type = finding.info_type.name
                pii_type = GCP_TO_PII_TYPE.get(info_type)
                
                if pii_type:
                    # Get detected text (quote)
                    detected_text = finding.quote if finding.quote else value
                    
                    # Get likelihood score (convert to 0-1 confidence)
                    likelihood_map = {
                        dlp_v2.Likelihood.VERY_UNLIKELY: 0.1,
                        dlp_v2.Likelihood.UNLIKELY: 0.3,
                        dlp_v2.Likelihood.POSSIBLE: 0.5,
                        dlp_v2.Likelihood.LIKELY: 0.7,
                        dlp_v2.Likelihood.VERY_LIKELY: 0.9,
                    }
                    confidence = likelihood_map.get(finding.likelihood, 0.5)
                    
                    detections.append(PIIDetection(
                        pii_type=pii_type,
                        confidence=confidence,
                        value=detected_text,
                        pattern_matched=detected_text,
                        field_name=field_name
                    ))
            
            return detections
        
        except gcp_exceptions.GoogleAPIError as e:
            logger.warning(f"GCP DLP API error: {e}")
            return []
        except Exception as e:
            logger.warning(f"GCP DLP detection error: {e}")
            return []
    
    def get_supported_entities(self) -> List[str]:
        """
        Get list of entities GCP DLP can detect.
        
        Returns:
            List of entity type names
        """
        if not self.is_available():
            return []
        
        return list(GCP_TO_PII_TYPE.keys())

