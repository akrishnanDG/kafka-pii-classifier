"""Field classification logic - aggregates PII detection results."""

import logging
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict
from dataclasses import dataclass, field

from .types import PIIDetection
from .types import PIIType, get_pii_tags

logger = logging.getLogger(__name__)


@dataclass
class FieldClassification:
    """Classification result for a field."""
    field_path: str
    pii_types: Set[PIIType]
    tags: List[str]
    confidence: float
    detection_count: int
    total_samples: int
    detection_rate: float
    sample_values: List[str] = field(default_factory=list)  # Sample field values that were detected as PII


class FieldClassifier:
    """Classifies fields based on aggregated PII detection results."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize field classifier.
        
        Args:
            config: Classification configuration
        """
        self.config = config
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.min_detection_rate = config.get('min_detection_rate', 0.3)
        self.require_multiple_detections = config.get('require_multiple_detections', True)
    
    def classify_field(
        self,
        field_path: str,
        detections: List[List[PIIDetection]],
        total_samples: int
    ) -> Optional[FieldClassification]:
        """
        Classify a field based on aggregated detections.
        
        Args:
            field_path: Field path
            detections: List of detection lists (one per sample)
            total_samples: Total number of samples analyzed
        
        Returns:
            FieldClassification if field should be tagged, None otherwise
        """
        if not detections:
            return None
        
        # Aggregate all detections and collect sample values
        all_detections = []
        samples_with_detections = 0
        sample_values_set = set()

        for sample_detections in detections:
            all_detections.extend(sample_detections)
            if sample_detections:
                samples_with_detections += 1
            for detection in sample_detections:
                if detection.value and len(sample_values_set) < 10:
                    sample_values_set.add(detection.value)

        if not all_detections:
            return None

        # Count detections by type
        type_counts = defaultdict(int)
        type_confidences = defaultdict(list)

        for detection in all_detections:
            type_counts[detection.pii_type] += 1
            type_confidences[detection.pii_type].append(detection.confidence)

        # Detection rate = fraction of samples that had at least one detection.
        # Multiple detectors may contribute separate entries for the same sample,
        # so cap at 1.0 to avoid rates > 100%.
        detection_count = samples_with_detections
        detection_rate = min(1.0, samples_with_detections / total_samples) if total_samples > 0 else 0.0
        
        # Filter by thresholds
        if self.require_multiple_detections and detection_count < 2:
            return None
        
        if detection_rate < self.min_detection_rate:
            return None
        
        # Get PII types that meet confidence threshold
        valid_types = set()
        avg_confidence = 0.0
        
        for pii_type, confidences in type_confidences.items():
            avg_type_confidence = sum(confidences) / len(confidences)
            if avg_type_confidence >= self.confidence_threshold:
                valid_types.add(pii_type)
                avg_confidence += avg_type_confidence
        
        if valid_types:
            avg_confidence = avg_confidence / len(valid_types)
        else:
            return None
        
        # Generate tags
        tags = ["PII"]  # General tag
        for pii_type in valid_types:
            tags.extend(get_pii_tags(pii_type))
        
        # Remove duplicates while preserving order
        tags = list(dict.fromkeys(tags))
        
        return FieldClassification(
            field_path=field_path,
            pii_types=valid_types,
            tags=tags,
            confidence=avg_confidence,
            detection_count=detection_count,
            total_samples=total_samples,
            detection_rate=detection_rate,
            sample_values=list(sample_values_set)[:10] if sample_values_set else []  # Limit to 10 samples
        )
    
    def classify_fields(
        self,
        field_detections: Dict[str, List[List[PIIDetection]]],
        total_samples: int
    ) -> Dict[str, FieldClassification]:
        """
        Classify all fields.
        
        Args:
            field_detections: Dictionary mapping field paths to detection lists
            total_samples: Total number of samples
        
        Returns:
            Dictionary mapping field paths to classifications
        """
        classifications = {}
        
        for field_path, detections in field_detections.items():
            classification = self.classify_field(field_path, detections, total_samples)
            if classification:
                classifications[field_path] = classification
        
        return classifications

