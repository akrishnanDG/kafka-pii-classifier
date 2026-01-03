"""Schema inference from JSON samples."""

import logging
from typing import Dict, Any, List, Set
from collections import defaultdict

from .json_parser import JSONParser
from ..utils.helpers import safe_json_parse

logger = logging.getLogger(__name__)


class SchemaInferrer:
    """Infer schema structure from JSON samples."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize schema inferrer.
        
        Args:
            config: Schema inference configuration
        """
        self.config = config
        self.json_parser = JSONParser(config.get('field_extraction', {}))
        self.min_samples = config.get('min_samples_for_inference', 10)
    
    def infer_schema(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Infer schema from multiple samples.
        
        Args:
            samples: List of parsed JSON samples
        
        Returns:
            Inferred schema structure
        """
        if len(samples) < self.min_samples:
            logger.warning(
                f"Only {len(samples)} samples available, "
                f"minimum {self.min_samples} recommended"
            )
        
        # Extract fields from all samples
        all_fields = defaultdict(list)  # field_path -> list of values
        
        for sample in samples:
            fields = self.json_parser.extract_fields(sample)
            for field_path, value in fields.items():
                all_fields[field_path].append(value)
        
        # Analyze field types
        inferred_schema = {}
        for field_path, values in all_fields.items():
            field_info = self._analyze_field(field_path, values)
            inferred_schema[field_path] = field_info
        
        return inferred_schema
    
    def _analyze_field(self, field_path: str, values: List[Any]) -> Dict[str, Any]:
        """
        Analyze a field to determine its type and properties.
        
        Args:
            field_path: Field path
            values: List of field values across samples
        
        Returns:
            Field metadata
        """
        if not values:
            return {"type": "unknown", "nullable": True}
        
        # Count non-null values
        non_null = [v for v in values if v is not None]
        nullable = len(non_null) < len(values)
        
        if not non_null:
            return {"type": "unknown", "nullable": True}
        
        # Determine type
        types = set()
        for value in non_null:
            if isinstance(value, bool):
                types.add("boolean")
            elif isinstance(value, int):
                types.add("integer")
            elif isinstance(value, float):
                types.add("number")
            elif isinstance(value, str):
                types.add("string")
            elif isinstance(value, list):
                types.add("array")
            elif isinstance(value, dict):
                types.add("object")
        
        # Choose most common type, or "string" if mixed
        if len(types) == 1:
            field_type = list(types)[0]
        elif "string" in types:
            field_type = "string"  # Default to string for mixed types
        else:
            field_type = list(types)[0]  # Pick first
        
        return {
            "type": field_type,
            "nullable": nullable,
            "sample_count": len(non_null),
            "total_count": len(values),
            "sample_values": non_null[:5]  # First 5 samples
        }

