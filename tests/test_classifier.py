"""Tests for FieldClassifier -- no mocks needed, test directly with PIIDetection."""

import pytest
from src.pii.types import PIIType, PIIDetection
from src.pii.classifier import FieldClassifier, FieldClassification


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detection(
    pii_type=PIIType.EMAIL,
    confidence=0.95,
    value='test@example.com',
    pattern='email_pattern',
    field_name=None,
):
    """Create a PIIDetection with sensible defaults."""
    return PIIDetection(
        pii_type=pii_type,
        confidence=confidence,
        value=value,
        pattern_matched=pattern,
        field_name=field_name,
    )


def _default_config(**overrides):
    config = {
        'confidence_threshold': 0.7,
        'min_detection_rate': 0.3,
        'require_multiple_detections': True,
    }
    config.update(overrides)
    return config


# ===================================================================
# classify_field -- empty detections
# ===================================================================

class TestClassifyFieldEmpty:
    """classify_field returns None for empty detections."""

    def test_none_for_empty_list(self):
        classifier = FieldClassifier(_default_config())
        result = classifier.classify_field('user.email', [], total_samples=10)
        assert result is None

    def test_none_for_list_of_empty_lists(self):
        """Detections list contains sub-lists that are all empty."""
        classifier = FieldClassifier(_default_config())
        result = classifier.classify_field('user.email', [[], []], total_samples=10)
        assert result is None


# ===================================================================
# classify_field -- below confidence threshold
# ===================================================================

class TestClassifyFieldBelowConfidence:
    """classify_field returns None below confidence threshold."""

    def test_returns_none_when_avg_confidence_below_threshold(self):
        classifier = FieldClassifier(_default_config(confidence_threshold=0.9))
        # All detections have confidence 0.5 -- well below 0.9
        detections = [
            [_make_detection(confidence=0.5)],
            [_make_detection(confidence=0.5)],
            [_make_detection(confidence=0.5)],
            [_make_detection(confidence=0.5)],
        ]
        result = classifier.classify_field('email', detections, total_samples=10)
        assert result is None

    def test_returns_none_when_confidence_is_exactly_below(self):
        classifier = FieldClassifier(_default_config(confidence_threshold=0.8))
        detections = [
            [_make_detection(confidence=0.79)],
            [_make_detection(confidence=0.79)],
            [_make_detection(confidence=0.79)],
            [_make_detection(confidence=0.79)],
        ]
        result = classifier.classify_field('email', detections, total_samples=10)
        assert result is None


# ===================================================================
# classify_field -- below detection rate
# ===================================================================

class TestClassifyFieldBelowDetectionRate:
    """classify_field returns None below detection rate."""

    def test_returns_none_when_detection_rate_too_low(self):
        classifier = FieldClassifier(_default_config(min_detection_rate=0.5))
        # Only 2 detections out of 100 samples = 0.02 rate
        detections = [
            [_make_detection()],
            [_make_detection()],
        ]
        result = classifier.classify_field('email', detections, total_samples=100)
        assert result is None

    @pytest.mark.parametrize(
        'n_detections,total_samples,min_rate',
        [
            (1, 10, 0.3),   # rate = 0.1
            (2, 20, 0.3),   # rate = 0.1
            (3, 100, 0.1),  # rate = 0.03
        ],
    )
    def test_parametrized_low_rate(self, n_detections, total_samples, min_rate):
        classifier = FieldClassifier(_default_config(min_detection_rate=min_rate))
        detections = [[_make_detection()] for _ in range(n_detections)]
        result = classifier.classify_field('email', detections, total_samples=total_samples)
        assert result is None


# ===================================================================
# classify_field -- valid data returns correct FieldClassification
# ===================================================================

class TestClassifyFieldValid:
    """classify_field returns correct FieldClassification with valid data."""

    def test_returns_classification_above_all_thresholds(self):
        classifier = FieldClassifier(_default_config(
            confidence_threshold=0.7,
            min_detection_rate=0.3,
            require_multiple_detections=True,
        ))
        detections = [
            [_make_detection(pii_type=PIIType.EMAIL, confidence=0.95, value='a@b.com')],
            [_make_detection(pii_type=PIIType.EMAIL, confidence=0.92, value='c@d.com')],
            [_make_detection(pii_type=PIIType.EMAIL, confidence=0.90, value='e@f.com')],
            [_make_detection(pii_type=PIIType.EMAIL, confidence=0.88, value='g@h.com')],
        ]
        result = classifier.classify_field('user.email', detections, total_samples=10)

        assert result is not None
        assert isinstance(result, FieldClassification)
        assert result.field_path == 'user.email'
        assert PIIType.EMAIL in result.pii_types
        assert result.detection_count == 4
        assert result.total_samples == 10
        assert result.detection_rate == pytest.approx(0.4)
        assert result.confidence >= 0.7
        assert 'PII' in result.tags
        assert 'PII-Email' in result.tags

    def test_sample_values_are_collected(self):
        classifier = FieldClassifier(_default_config(require_multiple_detections=False))
        detections = [
            [_make_detection(value='alice@example.com')],
            [_make_detection(value='bob@example.com')],
            [_make_detection(value='carol@example.com')],
            [_make_detection(value='dave@example.com')],
        ]
        result = classifier.classify_field('email', detections, total_samples=10)

        assert result is not None
        assert len(result.sample_values) > 0
        # sample_values should contain unique values from detections
        for sv in result.sample_values:
            assert '@' in sv

    def test_multiple_pii_types_in_single_field(self):
        """A field may trigger multiple PII types (e.g. value contains both
        an email and a name)."""
        classifier = FieldClassifier(_default_config(
            confidence_threshold=0.7,
            min_detection_rate=0.1,
            require_multiple_detections=True,
        ))
        detections = [
            [
                _make_detection(pii_type=PIIType.EMAIL, confidence=0.9, value='a@b.com'),
                _make_detection(pii_type=PIIType.NAME, confidence=0.85, value='Alice'),
            ],
            [
                _make_detection(pii_type=PIIType.EMAIL, confidence=0.9, value='c@d.com'),
                _make_detection(pii_type=PIIType.NAME, confidence=0.80, value='Bob'),
            ],
        ]
        result = classifier.classify_field('contact', detections, total_samples=5)

        assert result is not None
        assert PIIType.EMAIL in result.pii_types
        assert PIIType.NAME in result.pii_types
        assert 'PII-Email' in result.tags
        assert 'PII-Name' in result.tags


# ===================================================================
# classify_fields -- aggregation
# ===================================================================

class TestClassifyFields:
    """classify_fields aggregates correctly."""

    def test_aggregates_multiple_fields(self):
        classifier = FieldClassifier(_default_config(
            require_multiple_detections=True,
            min_detection_rate=0.1,
        ))
        field_detections = {
            'user.email': [
                [_make_detection(pii_type=PIIType.EMAIL, value='a@b.com')],
                [_make_detection(pii_type=PIIType.EMAIL, value='c@d.com')],
                [_make_detection(pii_type=PIIType.EMAIL, value='e@f.com')],
            ],
            'user.ssn': [
                [_make_detection(pii_type=PIIType.SSN, confidence=0.9, value='123-45-6789')],
                [_make_detection(pii_type=PIIType.SSN, confidence=0.9, value='987-65-4321')],
                [_make_detection(pii_type=PIIType.SSN, confidence=0.9, value='111-22-3333')],
            ],
            'user.id': [],  # No detections -> should not appear
        }
        classifications = classifier.classify_fields(field_detections, total_samples=10)

        assert 'user.email' in classifications
        assert 'user.ssn' in classifications
        assert 'user.id' not in classifications

    def test_skips_fields_that_do_not_meet_thresholds(self):
        classifier = FieldClassifier(_default_config(
            confidence_threshold=0.99,  # Very high
        ))
        field_detections = {
            'user.email': [
                [_make_detection(confidence=0.5)],
                [_make_detection(confidence=0.5)],
                [_make_detection(confidence=0.5)],
                [_make_detection(confidence=0.5)],
            ],
        }
        classifications = classifier.classify_fields(field_detections, total_samples=10)
        assert len(classifications) == 0


# ===================================================================
# require_multiple_detections setting
# ===================================================================

class TestRequireMultipleDetections:
    """Test require_multiple_detections setting."""

    def test_single_detection_rejected_when_required(self):
        classifier = FieldClassifier(_default_config(require_multiple_detections=True))
        detections = [
            [_make_detection()],
        ]
        result = classifier.classify_field('email', detections, total_samples=2)
        assert result is None

    def test_single_detection_accepted_when_not_required(self):
        classifier = FieldClassifier(_default_config(
            require_multiple_detections=False,
            min_detection_rate=0.1,
        ))
        detections = [
            [_make_detection(confidence=0.95)],
        ]
        result = classifier.classify_field('email', detections, total_samples=2)
        assert result is not None
        assert result.detection_count == 1

    def test_two_detections_pass_when_multiple_required(self):
        classifier = FieldClassifier(_default_config(
            require_multiple_detections=True,
            min_detection_rate=0.1,
        ))
        detections = [
            [_make_detection(confidence=0.9)],
            [_make_detection(confidence=0.9)],
        ]
        result = classifier.classify_field('email', detections, total_samples=5)
        assert result is not None
        assert result.detection_count == 2

    @pytest.mark.parametrize('require_multiple', [True, False])
    def test_zero_detections_always_returns_none(self, require_multiple):
        classifier = FieldClassifier(_default_config(
            require_multiple_detections=require_multiple,
        ))
        result = classifier.classify_field('email', [], total_samples=10)
        assert result is None
