"""JSON parsing and field extraction for schemaless topics."""

import json
import logging
from typing import Dict, Any, List, Set, Optional

from ..utils.helpers import safe_json_parse, flatten_dict

logger = logging.getLogger(__name__)


class JSONParser:
    """Parse JSON messages and extract fields."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize JSON parser.
        
        Args:
            config: Configuration for field extraction
        """
        self.config = config
        self.flatten_nested = config.get('flatten_nested', False)
        self.include_arrays = config.get('include_arrays', True)
        self.max_nesting_depth = config.get('max_nesting_depth', 10)
    
    def parse(self, message: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse JSON message.
        
        Args:
            message: Raw message bytes
        
        Returns:
            Parsed JSON dictionary or None if parsing fails
        """
        return safe_json_parse(message)
    
    def extract_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all fields from JSON structure.
        
        Args:
            data: Parsed JSON dictionary
        
        Returns:
            Dictionary of field paths to values
        """
        if self.flatten_nested:
            return flatten_dict(data, sep=".")
        else:
            return self._extract_fields_nested(data, prefix="")
    
    def _extract_fields_nested(
        self,
        data: Any,
        prefix: str = "",
        depth: int = 0
    ) -> Dict[str, Any]:
        """
        Extract fields preserving nested structure.
        
        Args:
            data: Data to extract from
            prefix: Field path prefix
            depth: Current nesting depth
        
        Returns:
            Dictionary of field paths to values
        """
        if depth > self.max_nesting_depth:
            return {}
        
        fields = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                field_path = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (dict, list)):
                    if isinstance(value, list) and self.include_arrays:
                        # Handle arrays
                        for i, item in enumerate(value):
                            if isinstance(item, (dict, list)):
                                nested = self._extract_fields_nested(
                                    item, f"{field_path}[{i}]", depth + 1
                                )
                                fields.update(nested)
                            else:
                                fields[f"{field_path}[{i}]"] = item
                    else:
                        nested = self._extract_fields_nested(
                            value, field_path, depth + 1
                        )
                        fields.update(nested)
                else:
                    fields[field_path] = value
        
        elif isinstance(data, list) and self.include_arrays:
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    nested = self._extract_fields_nested(
                        item, f"{prefix}[{i}]", depth + 1
                    )
                    fields.update(nested)
                else:
                    fields[f"{prefix}[{i}]"] = item
        
        return fields

