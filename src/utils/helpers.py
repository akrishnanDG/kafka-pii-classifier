"""Helper utility functions."""

import json
from typing import Any, Dict, List, Optional


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """
    Flatten a nested dictionary.
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for nested keys
    
    Returns:
        Flattened dictionary
    """
    items: List[tuple] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Handle lists by creating indexed keys
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, f"{new_key}[{i}]", sep=sep).items())
                else:
                    items.append((f"{new_key}[{i}]", item))
        else:
            items.append((new_key, v))
    return dict(items)


def safe_json_parse(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Safely parse JSON data, handling binary prefixes (e.g., Avro magic bytes).
    
    Args:
        data: Bytes to parse
    
    Returns:
        Parsed JSON dict or None if parsing fails
    """
    try:
        if isinstance(data, bytes):
            # Try to parse the entire bytes string first
            try:
                return json.loads(data.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If that fails, look for JSON start (usually '{' or '[')
                # This handles cases where there's a binary prefix (e.g., Avro magic bytes)
                json_start = data.find(b'{')
                if json_start == -1:
                    json_start = data.find(b'[')
                if json_start >= 0:
                    json_str = data[json_start:].decode('utf-8')
                    return json.loads(json_str)
                return None
        elif isinstance(data, str):
            return json.loads(data)
        elif isinstance(data, dict):
            return data
        return None
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None


def mask_pii(value: str, mask_char: str = "*", keep_last: int = 0) -> str:
    """
    Mask PII value for logging/reporting.
    
    Args:
        value: Value to mask
        mask_char: Character to use for masking
        keep_last: Number of characters to keep at the end
    
    Returns:
        Masked string
    """
    if not value or len(value) <= keep_last:
        return mask_char * len(value) if value else ""
    
    masked_length = len(value) - keep_last
    if keep_last == 0:
        return mask_char * masked_length
    return mask_char * masked_length + value[-keep_last:]


def sanitize_field_name(name: str) -> str:
    """
    Sanitize field name for use in tags or metadata.
    
    Args:
        name: Field name to sanitize
    
    Returns:
        Sanitized field name
    """
    # Replace special characters with underscores
    sanitized = "".join(c if c.isalnum() or c in ('_', '-', '.') else '_' for c in name)
    # Remove leading/trailing underscores
    return sanitized.strip('_')

