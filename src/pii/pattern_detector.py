"""Pattern-based PII detection using regex."""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any

from .base_detector import PIIDetectorBase
from .types import PIIType, PIIDetection

logger = logging.getLogger(__name__)


class PatternDetector(PIIDetectorBase):
    """Pattern-based PII detector using regex patterns."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize pattern detector with regex patterns.
        
        Args:
            config: Optional configuration dictionary (unused for pattern detector)
        """
        self.config = config or {}
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[PIIType, re.Pattern]:
        """Compile regex patterns for PII detection."""
        patterns = {
            # US SSN: XXX-XX-XXXX
            PIIType.SSN: re.compile(
                r'^\d{3}-\d{2}-\d{4}$|^\d{9}$'
            ),
            
            # Email addresses
            PIIType.EMAIL: re.compile(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            ),
            
            # Phone numbers (US and international formats)
            PIIType.PHONE_NUMBER: re.compile(
                r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
                r'|\+?\d{10,15}'
            ),
            
            # Credit card (basic pattern, will validate with Luhn)
            PIIType.CREDIT_CARD: re.compile(
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
            ),
            
            # IP addresses (IPv4 and IPv6)
            PIIType.IP_ADDRESS: re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IPv4
                r'|'
                r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # IPv6
            ),
            
            # Date of birth (common formats)
            PIIType.DATE_OF_BIRTH: re.compile(
                r'\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b'  # MM/DD/YYYY
                r'|'
                r'\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b'  # YYYY/MM/DD
            ),
            
            # Name pattern - capitalized words (first name, last name)
            # This is a basic pattern - field name hints will boost confidence
            PIIType.NAME: re.compile(
                r'^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+$'  # "John Smith", "Mary Jane Watson"
            ),
            
            # Bank Account Number (US format: 8-17 digits)
            PIIType.BANK_ACCOUNT: re.compile(
                r'^\d{8,17}$'
            ),
            
            # IBAN (International Bank Account Number)
            # Format: 2 letters (country code) + 2 digits (check) + up to 30 alphanumeric
            PIIType.IBAN: re.compile(
                r'^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$'
            ),
            
            # SWIFT/BIC Code (8 or 11 characters: 4 letters + 2 letters + 2 alphanumeric + optional 3 alphanumeric)
            PIIType.SWIFT_CODE: re.compile(
                r'^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$'
            ),
            
            # AWS Access Key (format: AKIA followed by 16 alphanumeric characters)
            PIIType.AWS_ACCESS_KEY: re.compile(
                r'^AKIA[0-9A-Z]{16}$'
            ),
            
            # AWS Secret Key (base64-like, 40 characters)
            PIIType.AWS_SECRET_KEY: re.compile(
                r'^[A-Za-z0-9/+=]{40}$'
            ),
            
            # ITIN (Individual Tax Identification Number - US)
            # Format: 9 digits, starts with 9, 4th digit is 7 or 8
            PIIType.ITIN: re.compile(
                r'^9\d{2}[78]\d{5}$'
            ),
            
            # UK National Insurance Number
            # Format: 2 letters, 6 digits, 1 letter (e.g., AB123456C)
            PIIType.NATIONAL_INSURANCE_NUMBER: re.compile(
                r'^[A-Z]{2}\d{6}[A-Z]?$'
            ),
            
            # MAC Address (format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
            PIIType.MAC_ADDRESS: re.compile(
                r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            ),
        }
        return patterns
    
    def detect(self, value: str, field_name: Optional[str] = None) -> List[PIIDetection]:
        """
        Detect PII in a value.
        
        Args:
            value: Value to check
            field_name: Optional field name (used for context hints)
        
        Returns:
            List of PII detections
        """
        if not value or not isinstance(value, str):
            return []
        
        detections = []
        value_clean = value.strip()
        
        # Check each pattern
        detected_types = set()
        for pii_type, pattern in self.patterns.items():
            match = pattern.search(value_clean)
            if match:
                confidence = self._calculate_confidence(
                    pii_type, value_clean, match.group(), field_name
                )

                # Only add detection if confidence > 0 (0 confidence means filtered out by field name context)
                if confidence > 0:
                    detections.append(PIIDetection(
                        pii_type=pii_type,
                        confidence=confidence,
                        value=value_clean,
                        pattern_matched=match.group(),
                        field_name=field_name
                    ))
                    detected_types.add(pii_type)

        # Field-name-based detection: if the field name strongly indicates PII
        # but no regex matched for that type, create a detection from the
        # field name hint alone. This catches single-word names (first_name,
        # last_name) and unstructured addresses (home_address) that regex
        # cannot match.
        if field_name:
            field_hints = self._detect_from_field_name(
                field_name, value_clean, detected_types
            )
            detections.extend(field_hints)

        return detections

    # Field name indicators and their PII types
    _FIELD_NAME_INDICATORS = {
        PIIType.NAME: [
            'first_name', 'firstname', 'last_name', 'lastname',
            'full_name', 'fullname', 'person_name', 'customer_name',
            'cardholder_name', 'account_name', 'user_name', 'driver_name',
            'passenger_name', 'employee_name', 'contact_name',
        ],
        PIIType.ADDRESS: [
            'address', 'home_address', 'street_address', 'mailing_address',
            'billing_address', 'shipping_address', 'residential_address',
        ],
    }

    def _detect_from_field_name(
        self,
        field_name: str,
        value: str,
        already_detected: set
    ) -> List[PIIDetection]:
        """Detect PII based on field name when regex didn't match.

        Only fires for NAME and ADDRESS types where regex coverage is weak
        (single-word names, unstructured addresses).
        """
        hints = []
        field_lower = field_name.lower().replace('-', '_')

        for pii_type, indicators in self._FIELD_NAME_INDICATORS.items():
            if pii_type in already_detected:
                continue
            if any(ind in field_lower for ind in indicators):
                # Basic validation: not empty, not purely numeric
                if len(value) < 2 or value.isdigit():
                    continue
                # For NAME: at least one letter
                if pii_type == PIIType.NAME and not any(c.isalpha() for c in value):
                    continue
                # For ADDRESS: at least 5 chars
                if pii_type == PIIType.ADDRESS and len(value) < 5:
                    continue

                hints.append(PIIDetection(
                    pii_type=pii_type,
                    confidence=0.85,
                    value=value,
                    pattern_matched=f"field_name_hint:{field_name}",
                    field_name=field_name,
                ))
        return hints
    
    def _calculate_confidence(
        self,
        pii_type: PIIType,
        value: str,
        matched: str,
        field_name: Optional[str]
    ) -> float:
        """
        Calculate confidence score for a detection.
        
        Args:
            pii_type: Type of PII detected
            value: Full value
            matched: Matched pattern
            field_name: Field name (for context hints)
        
        Returns:
            Confidence score (0.0 to 1.0)
        """
        base_confidence = 0.7
        
        # Field name hints boost confidence OR reduce it for false positives
        if field_name:
            field_lower = field_name.lower()
            
            # Negative context: If field name suggests this is NOT the PII type, reduce confidence significantly
            has_time_context = any(word in field_lower for word in ['time', 'timestamp', 'created_at', 'updated_at', 'modified_at', 'event_time', 'logged_at', 'occurred_at'])
            has_id_context = any(word in field_lower for word in ['id', 'identifier', 'vehicle_id', 'customer_id', 'user_id', 'account_id', 'order_id', 'product_id', 'transaction_id'])
            has_license_plate_context = any(word in field_lower for word in ['license_plate', 'licenseplate', 'plate', 'vehicle_plate', 'registration_plate'])
            
            # Time/timestamp fields should NOT be detected as phone numbers
            if pii_type == PIIType.PHONE_NUMBER and has_time_context:
                # This is likely a Unix timestamp, not a phone number
                return 0.0  # Return 0 confidence to effectively filter it out
            
            # License plate fields should NOT be detected as driver licenses, names, or addresses
            # License plate = vehicle registration plate (e.g., "ABC123")
            # Driver's license = person's license to drive (e.g., "D1234567")
            # These are different things!
            if has_license_plate_context:
                if pii_type == PIIType.DRIVER_LICENSE:
                    return 0.0  # License plate ≠ Driver's license
                elif pii_type == PIIType.NAME:
                    return 0.0  # License plate is not a name
                elif pii_type == PIIType.ADDRESS:
                    return 0.0  # License plate is not an address
            
            # Positive context: Boost confidence when field name matches PII type
            # New PII types field name hints
            if pii_type == PIIType.BANK_ACCOUNT and ('bank' in field_lower or 'account' in field_lower or 'routing' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.IBAN and 'iban' in field_lower:
                base_confidence = 0.95
            elif pii_type == PIIType.SWIFT_CODE and ('swift' in field_lower or 'bic' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.AWS_ACCESS_KEY and ('aws' in field_lower and 'access' in field_lower and 'key' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.AWS_SECRET_KEY and ('aws' in field_lower and 'secret' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.ITIN and 'itin' in field_lower:
                base_confidence = 0.95
            elif pii_type == PIIType.NATIONAL_INSURANCE_NUMBER and (('national' in field_lower and 'insurance' in field_lower) or 'ni_number' in field_lower or 'nino' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.USERNAME and ('username' in field_lower or 'user_name' in field_lower or 'login' in field_lower):
                base_confidence = 0.9
            elif pii_type == PIIType.PASSWORD and ('password' in field_lower or 'passwd' in field_lower or 'pwd' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.MAC_ADDRESS and ('mac' in field_lower and 'address' in field_lower):
                base_confidence = 0.9
            # Original field name hints
            if pii_type == PIIType.EMAIL and ('email' in field_lower or 'mail' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.SSN and 'ssn' in field_lower:
                base_confidence = 0.95
            elif pii_type == PIIType.PHONE_NUMBER and ('phone' in field_lower or 'tel' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.ADDRESS and 'address' in field_lower:
                base_confidence = 0.90
            elif pii_type == PIIType.CREDIT_CARD and ('card' in field_lower or 'credit' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.DATE_OF_BIRTH and ('dob' in field_lower or 'birth' in field_lower):
                base_confidence = 0.90
            elif pii_type == PIIType.IP_ADDRESS and ('ip' in field_lower):
                base_confidence = 0.95
            elif pii_type == PIIType.NAME and (
                'name' in field_lower or 
                'firstname' in field_lower or 
                'lastname' in field_lower or
                'fullname' in field_lower or
                'person' in field_lower
            ):
                base_confidence = 0.90
        
        # Additional validation for specific types
        if pii_type == PIIType.CREDIT_CARD:
            # Validate with Luhn algorithm
            if self._validate_luhn(matched.replace('-', '').replace(' ', '')):
                base_confidence = 0.95
            else:
                base_confidence = 0.5  # Pattern matched but not valid
        
        # SSN validation (basic checks)
        if pii_type == PIIType.SSN:
            # Check for invalid SSN patterns
            ssn_clean = matched.replace('-', '')
            if ssn_clean.startswith('000') or ssn_clean.startswith('666') or ssn_clean == '123456789':
                base_confidence = 0.3  # Likely invalid/test SSN
        
        # Name validation - reduce confidence for very short names or common words
        if pii_type == PIIType.NAME:
            name_parts = value.split()
            # If field name doesn't suggest name, reduce confidence
            if not field_name or 'name' not in field_name.lower():
                base_confidence = 0.5  # Lower confidence without field name hint
            # Single word names are less likely
            if len(name_parts) < 2:
                base_confidence = max(0.3, base_confidence - 0.2)
            # Very long names (likely not a person name)
            if len(name_parts) > 5:
                base_confidence = max(0.3, base_confidence - 0.2)
        
        return min(base_confidence, 1.0)
    
    def _validate_luhn(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Credit card number (digits only)
        
        Returns:
            True if valid
        """
        try:
            digits = [int(d) for d in card_number]
            checksum = 0
            
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 0:
                    checksum += digit
                else:
                    doubled = digit * 2
                    checksum += doubled if doubled < 10 else doubled - 9
            
            return checksum % 10 == 0
        except (ValueError, IndexError):
            return False
    
    def is_available(self) -> bool:
        """Pattern detector is always available (no external dependencies)."""
        return True
    
    def get_supported_entities(self) -> List[str]:
        """Get list of PII types this detector can identify."""
        return [pii_type.value for pii_type in self.patterns.keys()]

