"""Tests for PII detection capabilities (Pattern and Presidio)."""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pii.pattern_detector import PatternDetector
from src.pii.types import PIIType


class TestPatternDetectorCapabilities:
    """Test Pattern detector capabilities with various PII types."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    @pytest.mark.parametrize("pii_type,value,should_detect", [
        ("SSN", "123-45-6789", True),
        ("EMAIL", "test@example.com", True),
        ("PHONE_NUMBER", "555-123-4567", True),
        ("CREDIT_CARD", "4532-1234-5678-9010", True),
        ("IP_ADDRESS", "192.168.1.1", True),
        ("EMAIL", "invalid-email", False),
        ("SSN", "123-45-678", False),
    ])
    def test_pattern_detection(self, detector, pii_type, value, should_detect):
        """Test pattern detection for various PII types."""
        detections = detector.detect(value, f"test_{pii_type.lower()}")
        detected = any(d.pii_type == PIIType[pii_type] for d in detections)
        assert detected == should_detect, (
            f"{pii_type}: '{value}' - expected {'detected' if should_detect else 'not detected'}"
        )


class TestPresidioDetector:
    """Test Presidio detector capabilities."""

    def test_presidio_import(self):
        """Test that Presidio detector can be imported."""
        try:
            from src.pii.presidio_detector import PresidioDetector
            detector = PresidioDetector()
            if not detector.is_available():
                pytest.skip("Presidio not available (not installed)")
        except ImportError:
            pytest.skip("Presidio not installed")

    @pytest.mark.parametrize("value,expected_type", [
        ("John Smith", "NAME"),
        ("test@example.com", "EMAIL"),
        ("555-123-4567", "PHONE_NUMBER"),
    ])
    def test_presidio_detection(self, value, expected_type):
        """Test Presidio detection for various PII types."""
        try:
            from src.pii.presidio_detector import PresidioDetector
            detector = PresidioDetector()
            if not detector.is_available():
                pytest.skip("Presidio not available")
        except ImportError:
            pytest.skip("Presidio not installed")

        detections = detector.detect(value, "test_field")
        detected = any(d.pii_type.value == expected_type for d in detections)
        assert detected, f"'{value}' not detected as {expected_type}"


@pytest.mark.integration
class TestCombinedDetector:
    """Test combined Pattern + configured detector."""

    def test_combined_detector_initialization(self):
        """Test that PIIDetector can initialize with pattern provider."""
        from src.pii.detector import PIIDetector

        pii_config = {
            'providers': ['pattern'],
            'enabled_types': ['SSN', 'EMAIL', 'PHONE_NUMBER', 'CREDIT_CARD', 'IP_ADDRESS', 'NAME'],
        }
        detector = PIIDetector(pii_config)
        assert len(detector.detectors) >= 1
        assert any(d.get_name() == 'pattern' for d in detector.detectors)

    @pytest.mark.parametrize("field_name,value,expected_type", [
        ("email", "test@example.com", "EMAIL"),
        ("ssn", "123-45-6789", "SSN"),
        ("phone", "555-123-4567", "PHONE_NUMBER"),
    ])
    def test_combined_detection(self, field_name, value, expected_type):
        """Test combined detection for basic PII types."""
        from src.pii.detector import PIIDetector

        pii_config = {
            'providers': ['pattern'],
            'enabled_types': ['SSN', 'EMAIL', 'PHONE_NUMBER', 'CREDIT_CARD', 'IP_ADDRESS', 'NAME'],
        }
        detector = PIIDetector(pii_config)
        detections = detector.detect_in_field(field_name, value)
        detected = any(d.pii_type.value == expected_type for d in detections)
        assert detected, f"Field '{field_name}' with value '{value}' not detected as {expected_type}"
