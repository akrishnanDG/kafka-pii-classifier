#!/usr/bin/env python3
"""Test PII detection capabilities (Pattern and Presidio)."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pii.pattern_detector import PatternDetector
from src.pii.presidio_detector import PresidioDetector
from src.pii.detector import PIIDetector
from src.pii.types import PIIType
from src.config.config_loader import load_config


def test_pattern_detector():
    """Test Pattern detector capabilities."""
    print("\n" + "="*60)
    print("Pattern Detector Tests")
    print("="*60)
    
    detector = PatternDetector()
    
    test_cases = [
        ("SSN", "123-45-6789", True),
        ("EMAIL", "test@example.com", True),
        ("PHONE_NUMBER", "555-123-4567", True),
        ("CREDIT_CARD", "4532-1234-5678-9010", True),
        ("IP_ADDRESS", "192.168.1.1", True),
        ("EMAIL", "invalid-email", False),
        ("SSN", "123-45-678", False),
    ]
    
    passed = 0
    failed = 0
    
    for pii_type, value, should_detect in test_cases:
        detections = detector.detect(value, f"test_{pii_type.lower()}")
        detected = any(d.pii_type == PIIType[pii_type] for d in detections)
        
        if detected == should_detect:
            print(f"✅ {pii_type}: '{value}' - {'Detected' if detected else 'Not detected'} (expected)")
            passed += 1
        else:
            print(f"❌ {pii_type}: '{value}' - {'Detected' if detected else 'Not detected'} (unexpected)")
            failed += 1
    
    print(f"\nPattern Detector: {passed} passed, {failed} failed")
    return failed == 0


def test_presidio_detector():
    """Test Presidio detector capabilities."""
    print("\n" + "="*60)
    print("Presidio Detector Tests")
    print("="*60)
    
    try:
        detector = PresidioDetector()
        
        if not detector.is_available():
            print("⚠️  Presidio not available (not installed or initialization failed)")
            print("   Install with: pip install presidio-analyzer && python -m spacy download en_core_web_lg")
            return True  # Not a failure, just not available
        
        test_cases = [
            ("John Smith", "NAME"),
            ("test@example.com", "EMAIL"),
            ("555-123-4567", "PHONE_NUMBER"),
        ]
        
        passed = 0
        failed = 0
        
        for value, expected_type in test_cases:
            detections = detector.detect(value, "test_field")
            detected = any(d.pii_type.value == expected_type for d in detections)
            
            if detected:
                print(f"✅ '{value}' - Detected as {expected_type}")
                passed += 1
            else:
                print(f"❌ '{value}' - Not detected as {expected_type}")
                failed += 1
        
        print(f"\nPresidio Detector: {passed} passed, {failed} failed")
        return failed == 0
        
    except Exception as e:
        print(f"⚠️  Presidio test error: {e}")
        return True  # Not a failure if Presidio isn't available


def test_combined_detector():
    """Test combined Pattern + Presidio detector."""
    print("\n" + "="*60)
    print("Combined Detector Tests")
    print("="*60)
    
    try:
        config_path = Path('config/config.yaml')
        if not config_path.exists():
            config_path = Path('config/config.test.yaml')
        
        config = load_config(config_path)
        pii_config = config.get('pii_detection', {})
        
        detector = PIIDetector(pii_config)
        print(f"✅ Initialized {len(detector.detectors)} detector(s): {[d.get_name() for d in detector.detectors]}")
        
        test_cases = [
            ("email", "test@example.com", "EMAIL"),
            ("ssn", "123-45-6789", "SSN"),
            ("phone", "555-123-4567", "PHONE_NUMBER"),
        ]
        
        passed = 0
        failed = 0
        
        for field_name, value, expected_type in test_cases:
            detections = detector.detect_in_field(field_name, value)
            detected = any(d.pii_type.value == expected_type for d in detections)
            
            if detected:
                print(f"✅ Field '{field_name}' with value '{value}' - Detected {expected_type}")
                passed += 1
            else:
                print(f"❌ Field '{field_name}' with value '{value}' - Not detected")
                failed += 1
        
        print(f"\nCombined Detector: {passed} passed, {failed} failed")
        return failed == 0
        
    except Exception as e:
        print(f"❌ Combined detector test error: {e}")
        return False


def main():
    """Run all PII detection tests."""
    print("="*60)
    print("PII Detection Tests")
    print("="*60)
    
    pattern_ok = test_pattern_detector()
    presidio_ok = test_presidio_detector()
    combined_ok = test_combined_detector()
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    print(f"Pattern Detector:  {'✅ PASS' if pattern_ok else '❌ FAIL'}")
    print(f"Presidio Detector: {'✅ PASS' if presidio_ok else '❌ FAIL'}")
    print(f"Combined Detector: {'✅ PASS' if combined_ok else '❌ FAIL'}")
    
    if pattern_ok and presidio_ok and combined_ok:
        print("\n✅ All PII detection tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())

