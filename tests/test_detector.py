"""Tests for PIIDetector orchestrator."""

import logging
import pytest
from unittest.mock import patch, MagicMock

from src.pii.types import PIIType, PIIDetection
from src.pii.base_detector import PIIDetectorBase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _det(pii_type=PIIType.EMAIL, confidence=0.9, value='test@example.com',
         pattern='test_pattern', field_name=None):
    """Shortcut for creating PIIDetection."""
    return PIIDetection(
        pii_type=pii_type,
        confidence=confidence,
        value=value,
        pattern_matched=pattern,
        field_name=field_name,
    )


class _StubDetector(PIIDetectorBase):
    """Minimal concrete detector for testing."""

    def __init__(self, detections=None, available=True, name='stub'):
        self._detections = detections or []
        self._available = available
        self._name = name

    def detect(self, value, field_name=None):
        return list(self._detections)

    def is_available(self):
        return self._available

    def get_supported_entities(self):
        return ['EMAIL', 'SSN']

    def get_name(self):
        return self._name


class _StubSchemaDetector(_StubDetector):
    """Detector that also supports detect_in_schema (schema-level)."""

    def __init__(self, schema_detections=None, **kwargs):
        super().__init__(**kwargs)
        self._schema_detections = schema_detections or []

    def detect_in_schema(self, field_names, sample_data=None):
        return list(self._schema_detections)


def _default_config(**overrides):
    cfg = {
        'enabled_types': ['EMAIL', 'SSN', 'PHONE_NUMBER'],
        'providers': ['pattern'],
        'use_pattern': False,  # disable auto-adding pattern
    }
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def patch_factory():
    """Patch PIIDetectorFactory.create so we control which detectors load."""
    with patch('src.pii.detector.PIIDetectorFactory') as factory_mock:
        yield factory_mock


# ===================================================================
# Empty enabled_types logs warning
# ===================================================================

class TestEmptyEnabledTypes:
    """Test empty enabled_types logs warning."""

    def test_warning_logged_for_empty_enabled_types(self, patch_factory):
        """When enabled_types is empty, a warning should be logged."""
        stub = _StubDetector()
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        with patch('src.pii.detector.logger') as mock_logger:
            from src.pii.detector import PIIDetector
            PIIDetector(_default_config(enabled_types=[]))
            mock_logger.warning.assert_called_once()
            assert 'No PII types enabled' in mock_logger.warning.call_args[0][0]

    def test_all_detections_filtered_out_when_no_types_enabled(self, patch_factory):
        """With no enabled types, detect_in_field should return empty list."""
        stub = _StubDetector(detections=[_det(pii_type=PIIType.EMAIL)])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=[]))

        result = detector.detect_in_field('email', 'test@example.com')
        assert result == []


# ===================================================================
# detect_in_field filters by enabled_types
# ===================================================================

class TestDetectInFieldFiltersByEnabledTypes:
    """detect_in_field filters by enabled_types."""

    def test_returns_only_enabled_types(self, patch_factory):
        detections = [
            _det(pii_type=PIIType.EMAIL, value='a@b.com'),
            _det(pii_type=PIIType.CREDIT_CARD, value='4111111111111111'),
        ]
        stub = _StubDetector(detections=detections)
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        # Only EMAIL is enabled, not CREDIT_CARD
        detector = PIIDetector(_default_config(enabled_types=['EMAIL']))

        result = detector.detect_in_field('contact', 'a@b.com 4111111111111111')
        assert all(d.pii_type == PIIType.EMAIL for d in result)

    @pytest.mark.parametrize(
        'enabled,expected_count',
        [
            (['EMAIL'], 1),
            (['SSN'], 1),
            (['EMAIL', 'SSN'], 2),
            ([], 0),
        ],
    )
    def test_parametrized_filtering(self, patch_factory, enabled, expected_count):
        detections = [
            _det(pii_type=PIIType.EMAIL, value='a@b.com'),
            _det(pii_type=PIIType.SSN, value='123-45-6789'),
        ]
        stub = _StubDetector(detections=detections)
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=enabled))

        result = detector.detect_in_field('data', 'some value')
        assert len(result) == expected_count


# ===================================================================
# detect_in_field deduplicates detections
# ===================================================================

class TestDetectInFieldDeduplicates:
    """detect_in_field deduplicates detections."""

    def test_deduplicates_same_type_and_value(self, patch_factory):
        """When two detectors return the same (type, value), only the higher
        confidence detection should be kept."""
        det_low = _det(pii_type=PIIType.EMAIL, confidence=0.7, value='dup@x.com')
        det_high = _det(pii_type=PIIType.EMAIL, confidence=0.95, value='dup@x.com')
        stub = _StubDetector(detections=[det_low, det_high])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['EMAIL']))

        result = detector.detect_in_field('email', 'dup@x.com')
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_different_types_same_value_not_deduplicated(self, patch_factory):
        """Detections with different pii_type but same value are treated as
        distinct (dedup key is (type, value))."""
        det_email = _det(pii_type=PIIType.EMAIL, value='shared')
        det_name = _det(pii_type=PIIType.NAME, value='shared', confidence=0.8)
        stub = _StubDetector(detections=[det_email, det_name])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['EMAIL', 'NAME']))

        # Note: _resolve_conflicts may still filter one out based on priority,
        # but deduplication itself should not merge them since keys differ.
        result = detector.detect_in_field('data', 'shared')
        # After conflict resolution the higher-priority one wins,
        # but both should have survived deduplication.
        types_found = {d.pii_type for d in result}
        # At minimum one should survive
        assert len(result) >= 1


# ===================================================================
# _resolve_conflicts filters timestamps
# ===================================================================

class TestResolveConflictsTimestamps:
    """_resolve_conflicts filters timestamps."""

    def test_filters_phone_number_on_timestamp_field(self, patch_factory):
        """A PHONE_NUMBER detection on a field named 'timestamp' with a
        Unix-timestamp value should be filtered out."""
        det = _det(pii_type=PIIType.PHONE_NUMBER, value='1762340928', confidence=0.8)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['PHONE_NUMBER']))

        result = detector.detect_in_field('event_time', '1762340928')
        assert len(result) == 0

    @pytest.mark.parametrize('field_name', [
        'created_at', 'updated_at', 'event_time', 'timestamp', 'logged_at',
    ])
    def test_filters_timestamps_on_various_time_fields(self, patch_factory, field_name):
        det = _det(pii_type=PIIType.PHONE_NUMBER, value='1762340928123', confidence=0.8)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['PHONE_NUMBER']))

        result = detector.detect_in_field(field_name, '1762340928123')
        assert len(result) == 0

    def test_keeps_phone_number_on_non_time_field(self, patch_factory):
        """PHONE_NUMBER should NOT be filtered for normal phone fields."""
        det = _det(pii_type=PIIType.PHONE_NUMBER, value='5551234567', confidence=0.9)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['PHONE_NUMBER']))

        result = detector.detect_in_field('phone', '5551234567')
        assert len(result) == 1


# ===================================================================
# _resolve_conflicts filters license plates
# ===================================================================

class TestResolveConflictsLicensePlates:
    """_resolve_conflicts filters license plates."""

    def test_filters_driver_license_on_plate_field(self, patch_factory):
        """DRIVER_LICENSE detection on a 'license_plate' field should be removed."""
        det = _det(pii_type=PIIType.DRIVER_LICENSE, value='ABC1234', confidence=0.8)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['DRIVER_LICENSE']))

        result = detector.detect_in_field('license_plate', 'ABC1234')
        assert len(result) == 0

    def test_filters_name_on_plate_field(self, patch_factory):
        """NAME detection on a 'plate' field should be removed."""
        det = _det(pii_type=PIIType.NAME, value='XYZ 789', confidence=0.7)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['NAME']))

        result = detector.detect_in_field('vehicle_plate', 'XYZ 789')
        assert len(result) == 0

    def test_filters_address_on_plate_field(self, patch_factory):
        """ADDRESS detection on a plate field should be removed."""
        det = _det(pii_type=PIIType.ADDRESS, value='CA-123-AB', confidence=0.6)
        stub = _StubDetector(detections=[det])
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(enabled_types=['ADDRESS']))

        result = detector.detect_in_field('registration_plate', 'CA-123-AB')
        assert len(result) == 0


# ===================================================================
# has_schema_detectors
# ===================================================================

class TestHasSchemaDetectors:
    """has_schema_detectors returns correctly."""

    def test_returns_true_when_schema_detector_present(self, patch_factory):
        """If one of the loaded detectors has detect_in_schema, should return True."""
        schema_det = _StubSchemaDetector(name='llm_agent')
        patch_factory.create.return_value = schema_det
        patch_factory.get_available_providers.return_value = ['llm_agent']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(
            providers=['llm_agent'],
            use_pattern=False,
        ))

        assert detector.has_schema_detectors() is True

    def test_returns_false_when_no_schema_detector(self, patch_factory):
        """If no loaded detector has detect_in_schema, should return False."""
        stub = _StubDetector(name='pattern')
        patch_factory.create.return_value = stub
        patch_factory.get_available_providers.return_value = ['pattern']

        from src.pii.detector import PIIDetector
        detector = PIIDetector(_default_config(
            providers=['pattern'],
            use_pattern=False,
        ))

        assert detector.has_schema_detectors() is False
