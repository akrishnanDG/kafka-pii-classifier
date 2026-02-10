"""Main PII detection orchestrator."""

import logging
import re
from typing import Dict, List, Optional, Any
from .types import PIIDetection, PIIType
from .factory import PIIDetectorFactory

logger = logging.getLogger(__name__)


def _has_schema_detection(detector) -> bool:
    """Check if a detector supports schema-level detection."""
    return hasattr(detector, 'detect_in_schema') and callable(getattr(detector, 'detect_in_schema', None))


class PIIDetector:
    """Main PII detection orchestrator."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize PII detector.
        
        Args:
            config: PII detection configuration with:
                - provider: Primary provider name (e.g., "llm_agent", "presidio", "aws", "gcp", "azure")
                - providers: List of provider names to use (default: ["pattern", "llm_agent"])
                - use_pattern: Whether to use pattern detector (default: True)
        """
        self.config = config
        enabled_list = config.get('enabled_types', [])
        self.enabled_types = set(PIIType[pt] for pt in enabled_list)
        if not self.enabled_types:
            logger.warning(
                "No PII types enabled in 'enabled_types' config. "
                "All detections will be filtered out. Add types like "
                "['SSN', 'EMAIL', 'PHONE_NUMBER'] to enabled_types."
            )
        
        # Initialize detectors based on configuration
        self.detectors = []
        
        # Get providers from config
        providers = config.get('providers', [])
        
        # If single provider specified
        if 'provider' in config:
            providers = [config['provider']]
        
        # Default: use pattern and llm_agent if nothing specified
        if not providers:
            providers = ['pattern', 'llm_agent']
        
        # Always include pattern detector if use_pattern is True (default)
        use_pattern = config.get('use_pattern', True)
        if use_pattern and 'pattern' not in providers:
            providers.insert(0, 'pattern')
        
        # Initialize each provider
        for provider_name in providers:
            try:
                detector = PIIDetectorFactory.create(provider_name, config)
                if detector.is_available():
                    self.detectors.append(detector)
                    logger.info(f"Initialized PII detector: {provider_name}")
                else:
                    logger.warning(f"PII detector {provider_name} is not available, skipping")
            except Exception as e:
                logger.warning(f"Failed to initialize PII detector {provider_name}: {e}")
                # Continue with other providers
                continue
        
        if not self.detectors:
            raise ValueError(
                "No PII detectors available. Please check your configuration and dependencies. "
                f"Available providers: {', '.join(PIIDetectorFactory.get_available_providers())}"
            )
        
        # Separate schema-level detectors (like llm_agent) from per-field detectors
        self.schema_detectors = [d for d in self.detectors if _has_schema_detection(d)]
        self.field_detectors = [d for d in self.detectors if not _has_schema_detection(d)]
        
        if self.schema_detectors:
            logger.info(f"Schema-level detectors: {[d.get_name() for d in self.schema_detectors]}")
        logger.info(f"Initialized {len(self.detectors)} PII detector(s): {[d.get_name() for d in self.detectors]}")
    
    def detect_in_schema(
        self,
        field_names: List[str],
        sample_data: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, List[PIIDetection]]:
        """
        Detect PII at schema level using LLM agent (efficient).
        
        This method is called ONCE per topic with all fields and samples,
        instead of calling detect() for each field value.
        
        Args:
            field_names: List of all field names in the schema
            sample_data: Optional list of sample records
        
        Returns:
            Dictionary mapping field names to detections
        """
        field_detections: Dict[str, List[PIIDetection]] = {}
        
        # Run schema-level detectors (like llm_agent)
        for detector in self.schema_detectors:
            try:
                logger.info(f"Running schema-level detection with {detector.get_name()}...")
                detections = detector.detect_in_schema(field_names, sample_data)
                
                # Group detections by field name
                for det in detections:
                    if det.field_name:
                        if det.field_name not in field_detections:
                            field_detections[det.field_name] = []
                        # Only add if type is enabled
                        if det.pii_type in self.enabled_types:
                            field_detections[det.field_name].append(det)
                            
                logger.info(f"Schema-level detection found {len(detections)} PII fields")
                
            except Exception as e:
                logger.error(f"Schema-level detection failed for {detector.get_name()}: {e}")
        
        return field_detections
    
    def has_schema_detectors(self) -> bool:
        """Check if any schema-level detectors are configured."""
        return len(self.schema_detectors) > 0
    
    def detect_in_field(self, field_name: str, value: Any) -> List[PIIDetection]:
        """
        Detect PII in a field value using configured detectors.
        
        Args:
            field_name: Field name
            value: Field value
        
        Returns:
            List of PII detections
        """
        if not isinstance(value, str):
            value = str(value)
        
        detections = []
        
        # Run per-field detectors only (schema detectors are called via detect_in_schema)
        for detector in self.field_detectors:
            try:
                detector_detections = detector.detect(value, field_name)
                detections.extend(detector_detections)
            except Exception as e:
                logger.warning(f"PII detection failed for {detector.get_name()} on field {field_name}: {e}")
                # Continue with other detectors
        
        # Remove duplicates (same PII type, same value)
        # Prefer higher confidence detections
        seen = {}
        for det in detections:
            key = (det.pii_type, det.value)
            if key not in seen or det.confidence > seen[key].confidence:
                seen[key] = det
        detections = list(seen.values())
        
        # Resolve conflicts - remove false positives
        # Note: value is already converted to string here
        detections = self._resolve_conflicts(detections, field_name, str(value))
        
        # Filter by enabled types
        detections = [
            d for d in detections
            if d.pii_type in self.enabled_types
        ]
        
        return detections
    
    def _resolve_conflicts(
        self, 
        detections: List[PIIDetection], 
        field_name: str, 
        value: str
    ) -> List[PIIDetection]:
        """
        Resolve conflicting PII detections and filter false positives.
        
        NOTE: Presidio's context enhancement is ONE-WAY (BOOST only). It doesn't understand
        field names as negative context (e.g., "time:" doesn't mean "NOT a phone number").
        Therefore, we filter false positives here based on field name context.
        
        Rules:
        0a. Filter PHONE_NUMBER false positives for timestamp/time fields (Unix timestamps match phone pattern)
        0b. Filter DATE_OF_BIRTH false positives for ID fields with numeric values
        1. If pattern detector validates credit card (Luhn), prefer CREDIT_CARD over DATE_OF_BIRTH/PHONE_NUMBER
        2. Use field name context (e.g., "card" in name -> prefer CREDIT_CARD)
        3. Prefer more specific types over generic ones
        4. Remove overlapping detections with lower confidence
        """
        # Note: Don't return early - we need to run filters even for single detections
        
        # PII type priority (higher = more important)
        type_priority = {
            PIIType.CREDIT_CARD: 100,  # High priority - has validation
            PIIType.SSN: 90,
            PIIType.PHONE_NUMBER: 85,
            PIIType.EMAIL: 85,
            PIIType.IP_ADDRESS: 80,
            PIIType.DRIVER_LICENSE: 75,
            PIIType.PASSPORT: 75,
            PIIType.ADDRESS: 70,
            PIIType.NAME: 65,
            PIIType.DATE_OF_BIRTH: 50,  # Lower priority - often false positive
        }
        
        # Check if pattern detector validated as credit card
        pattern_validated_credit_card = any(
            d.pii_type == PIIType.CREDIT_CARD and hasattr(d, 'pattern_matched')
            for d in detections
        )
        
        # Use field name context
        field_lower = field_name.lower() if field_name else ""
        has_card_context = any(word in field_lower for word in ['card', 'credit', 'cc', 'payment'])
        has_date_context = any(word in field_lower for word in ['date', 'birth', 'dob', 'age'])
        has_id_context = any(word in field_lower for word in ['id', 'identifier', 'vehicle_id', 'customer_id', 'user_id', 'account_id', 'order_id', 'product_id', 'transaction_id'])
        has_time_context = any(word in field_lower for word in ['time', 'timestamp', 'created_at', 'updated_at', 'modified_at', 'event_time', 'logged_at', 'occurred_at'])
        has_license_plate_context = any(word in field_lower for word in ['license_plate', 'licenseplate', 'plate', 'vehicle_plate', 'registration_plate'])
        
        resolved = []
        for det in detections:
            should_keep = True
            
            # Rule 0a: Filter PHONE_NUMBER false positives for timestamp/time fields
            # Unix timestamps (10-13 digits) match phone number pattern but are timestamps
            if det.pii_type == PIIType.PHONE_NUMBER and has_time_context:
                value_str = str(value).strip()
                # Check if it's a numeric timestamp (10-13 digits, possibly with decimal)
                # Unix timestamps: 10 digits (seconds) or 13 digits (milliseconds)
                # Match pure numeric (10-13 digits) or numeric with decimal (e.g., 1762340928.947)
                if re.match(r'^\d{10,13}(\.\d+)?$', value_str):
                    # This is a Unix timestamp, not a phone number
                    logger.debug(f"Filtering out PHONE_NUMBER false positive: {field_name}={value} (Unix timestamp)")
                    continue
            
            # Rule 0b: Filter false positives for license_plate fields
            # License plates (vehicle registration plates) are NOT driver licenses, names, or addresses
            if has_license_plate_context:
                if det.pii_type == PIIType.DRIVER_LICENSE:
                    # License plate ≠ Driver's license (different things)
                    logger.debug(f"Filtering out DRIVER_LICENSE false positive: {field_name}={value} (license plate, not driver license)")
                    continue
                elif det.pii_type == PIIType.NAME:
                    # License plate is not a person's name
                    logger.debug(f"Filtering out NAME false positive: {field_name}={value} (license plate, not name)")
                    continue
                elif det.pii_type == PIIType.ADDRESS:
                    # License plate is not an address
                    logger.debug(f"Filtering out ADDRESS false positive: {field_name}={value} (license plate, not address)")
                    continue
            
            # Rule 0c: Filter DATE_OF_BIRTH false positives for ID fields
            # Numeric IDs (like vehicle_id: 6538) are often misclassified as dates by Presidio
            if det.pii_type == PIIType.DATE_OF_BIRTH and has_id_context:
                value_str = str(value).strip()
                det_value_str = str(det.value).strip()
                if value_str.isdigit() or det_value_str.isdigit():
                    # Skip this detection - it's a numeric ID, not a date
                    logger.debug(f"Filtering out DATE_OF_BIRTH false positive: {field_name}={value} (numeric ID)")
                    continue
            
            # Rule 1: If pattern-validated credit card exists, remove DATE_OF_BIRTH and PHONE_NUMBER for same value
            credit_card_det = next(
                (d for d in detections if d.pii_type == PIIType.CREDIT_CARD and d.value == det.value),
                None
            )
            if credit_card_det and pattern_validated_credit_card:
                # Pattern detector validated this as a credit card (Luhn algorithm), so it's definitely a credit card
                if det.pii_type == PIIType.DATE_OF_BIRTH:
                    logger.debug(f"Removing DATE_OF_BIRTH false positive for value '{det.value}' (pattern-validated as CREDIT_CARD)")
                    should_keep = False
                elif det.pii_type == PIIType.PHONE_NUMBER:
                    logger.debug(f"Removing PHONE_NUMBER false positive for value '{det.value}' (pattern-validated as CREDIT_CARD)")
                    should_keep = False
            
            # Rule 2: Use field name context
            if has_card_context:
                # Field name suggests card - remove PHONE_NUMBER and DATE_OF_BIRTH false positives
                if det.pii_type == PIIType.DATE_OF_BIRTH:
                    logger.debug(f"Removing DATE_OF_BIRTH detection for field '{field_name}' (field suggests credit card)")
                    should_keep = False
                elif det.pii_type == PIIType.PHONE_NUMBER and credit_card_det:
                    # If we also detected credit card, prefer credit card over phone number
                    logger.debug(f"Removing PHONE_NUMBER detection for field '{field_name}' (field suggests credit card and CREDIT_CARD detected)")
                    should_keep = False
            elif has_date_context and det.pii_type == PIIType.CREDIT_CARD:
                # Field name suggests date, but detected as card - check confidence
                if det.confidence < 0.8:  # Lower confidence, likely false positive
                    logger.debug(f"Removing CREDIT_CARD detection for field '{field_name}' (field suggests date, low confidence)")
                    should_keep = False
            
            # Rule 3: If same value detected as multiple types, prefer higher priority type
            if should_keep:
                conflicting = [
                    d for d in detections
                    if d.value == det.value and d.pii_type != det.pii_type
                ]
                if conflicting:
                    det_priority = type_priority.get(det.pii_type, 0)
                    conflicting_priorities = [type_priority.get(c.pii_type, 0) for c in conflicting]
                    if conflicting_priorities and max(conflicting_priorities) > det_priority:
                        # Another type with higher priority exists for same value
                        higher_priority_det = next(
                            (c for c in conflicting if type_priority.get(c.pii_type, 0) == max(conflicting_priorities)),
                            None
                        )
                        if higher_priority_det and higher_priority_det.confidence >= det.confidence:
                            logger.debug(
                                f"Removing {det.pii_type} detection for value '{det.value}' "
                                f"(conflicts with higher priority {higher_priority_det.pii_type})"
                            )
                            should_keep = False
            
            if should_keep:
                resolved.append(det)
            else:
                # Debug: log when we're filtering out a detection
                logger.debug(f"Filtered out {det.pii_type.value} detection for field '{field_name}': {det.value}")
        
        return resolved
    
    def detect_in_message(self, message: Dict[str, Any]) -> Dict[str, List[PIIDetection]]:
        """
        Detect PII in all fields of a message.
        
        Args:
            message: Message dictionary (flat or nested)
        
        Returns:
            Dictionary mapping field names to detections
        """
        from ..utils.helpers import flatten_dict
        
        # Flatten nested structures
        flat_message = flatten_dict(message)
        
        field_detections = {}
        for field_path, value in flat_message.items():
            detections = self.detect_in_field(field_path, value)
            if detections:
                field_detections[field_path] = detections
        
        return field_detections

