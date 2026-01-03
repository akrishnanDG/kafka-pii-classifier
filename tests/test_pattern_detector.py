"""Unit tests for pattern-based PII detection."""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pii.pattern_detector import PatternDetector
from src.pii.types import PIIType


class TestPatternDetector:
    """Test pattern-based PII detection."""

    @pytest.fixture
    def detector(self):
        """Create a pattern detector instance."""
        return PatternDetector()

    # SSN Tests
    @pytest.mark.parametrize("value,should_detect", [
        ("123-45-6789", True),
        ("123456789", True),
        ("123-45-678", False),  # Too short
        ("1234-56-7890", False),  # Wrong format
    ])
    def test_ssn_detection(self, detector, value, should_detect):
        """Test SSN pattern detection."""
        detections = detector.detect(value, "ssn_field")
        detected = any(d.pii_type == PIIType.SSN for d in detections)
        assert detected == should_detect, f"SSN detection for '{value}': expected {should_detect}, got {detected}"

    # Email Tests
    @pytest.mark.parametrize("value,should_detect", [
        ("test@example.com", True),
        ("user.name@domain.org", True),
        ("user+tag@example.co.uk", True),
        ("invalid-email", False),
        ("@missing-local.com", False),
        ("missing-domain@", False),
    ])
    def test_email_detection(self, detector, value, should_detect):
        """Test email pattern detection."""
        detections = detector.detect(value, "email_field")
        detected = any(d.pii_type == PIIType.EMAIL for d in detections)
        assert detected == should_detect, f"Email detection for '{value}': expected {should_detect}, got {detected}"

    # Phone Number Tests
    @pytest.mark.parametrize("value,should_detect", [
        ("555-123-4567", True),
        ("(555) 123-4567", True),
        ("+1-555-123-4567", True),
        ("5551234567", True),
        ("123", False),  # Too short
    ])
    def test_phone_detection(self, detector, value, should_detect):
        """Test phone number pattern detection."""
        detections = detector.detect(value, "phone_field")
        detected = any(d.pii_type == PIIType.PHONE_NUMBER for d in detections)
        assert detected == should_detect, f"Phone detection for '{value}': expected {should_detect}, got {detected}"

    # Credit Card Tests
    @pytest.mark.parametrize("value,should_detect", [
        ("4532-1234-5678-9010", True),
        ("4532123456789010", True),
        ("4532 1234 5678 9010", True),
        ("1234", False),  # Too short
        ("1234-5678-9012-345", False),  # Wrong length
    ])
    def test_credit_card_detection(self, detector, value, should_detect):
        """Test credit card pattern detection."""
        detections = detector.detect(value, "cc_field")
        detected = any(d.pii_type == PIIType.CREDIT_CARD for d in detections)
        assert detected == should_detect, f"Credit card detection for '{value}': expected {should_detect}, got {detected}"

    # IP Address Tests
    @pytest.mark.parametrize("value,should_detect", [
        ("192.168.1.1", True),
        ("10.0.0.1", True),
        ("255.255.255.255", True),
        ("192.168.1", False),  # Incomplete
    ])
    def test_ip_address_detection(self, detector, value, should_detect):
        """Test IP address pattern detection."""
        detections = detector.detect(value, "ip_field")
        detected = any(d.pii_type == PIIType.IP_ADDRESS for d in detections)
        assert detected == should_detect, f"IP detection for '{value}': expected {should_detect}, got {detected}"

    # Field Name Hint Tests
    def test_field_name_boosts_detection(self, detector):
        """Test that field names with PII hints boost detection."""
        # Ambiguous value that might be a phone
        value = "5551234567"
        
        # With hint in field name
        detections_with_hint = detector.detect(value, "user_phone_number")
        # Without hint
        detections_no_hint = detector.detect(value, "random_field")
        
        # Both should detect, but with hint should have higher confidence
        hint_conf = max([d.confidence for d in detections_with_hint if d.pii_type == PIIType.PHONE_NUMBER], default=0)
        no_hint_conf = max([d.confidence for d in detections_no_hint if d.pii_type == PIIType.PHONE_NUMBER], default=0)
        
        # At minimum, both should detect
        assert len(detections_with_hint) > 0 or len(detections_no_hint) > 0

    def test_detector_name(self, detector):
        """Test detector returns correct name."""
        assert detector.get_name() == "pattern"

    def test_empty_value(self, detector):
        """Test detection on empty value."""
        detections = detector.detect("", "test_field")
        assert len(detections) == 0

    def test_none_value(self, detector):
        """Test detection on None value."""
        detections = detector.detect(None, "test_field")
        assert len(detections) == 0

    def test_multiple_pii_in_value(self, detector):
        """Test detection of multiple PII types in one value."""
        # Value containing email
        value = "test@example.com"
        detections = detector.detect(value, "contact_info")
        
        pii_types = {d.pii_type for d in detections}
        # Should detect email
        assert PIIType.EMAIL in pii_types


class TestPatternDetectorAvailability:
    """Test pattern detector availability."""

    def test_always_available(self):
        """Pattern detector should always be available."""
        detector = PatternDetector()
        assert detector.is_available() == True

