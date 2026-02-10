"""Unit tests for utility helper functions."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.helpers import flatten_dict, safe_json_parse, mask_pii, sanitize_field_name


class TestFlattenDict:
    """Test dictionary flattening."""

    def test_flat_dict(self):
        result = flatten_dict({"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_nested_dict(self):
        result = flatten_dict({"a": {"b": {"c": 1}}})
        assert result == {"a.b.c": 1}

    def test_list_values(self):
        result = flatten_dict({"a": [1, 2, 3]})
        assert result == {"a[0]": 1, "a[1]": 2, "a[2]": 3}

    def test_nested_list_of_dicts(self):
        result = flatten_dict({"a": [{"b": 1}]})
        assert result == {"a[0].b": 1}

    def test_empty_dict(self):
        result = flatten_dict({})
        assert result == {}


class TestSafeJsonParse:
    """Test JSON parsing."""

    def test_parse_bytes(self):
        result = safe_json_parse(b'{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_string(self):
        result = safe_json_parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_invalid_json(self):
        result = safe_json_parse(b'not json')
        assert result is None

    def test_parse_dict_passthrough(self):
        d = {"key": "value"}
        result = safe_json_parse(d)
        assert result == d

    def test_parse_non_dict_returns_none(self):
        result = safe_json_parse(12345)
        assert result is None

    def test_parse_bytes_with_prefix(self):
        # Simulate Avro magic bytes prefix
        data = b'\x00\x00\x00\x00\x01{"key": "value"}'
        result = safe_json_parse(data)
        assert result == {"key": "value"}


class TestMaskPii:
    """Test PII masking."""

    def test_full_mask(self):
        result = mask_pii("123-45-6789")
        assert result == "***********"

    def test_keep_last(self):
        result = mask_pii("123-45-6789", keep_last=4)
        assert result == "*******6789"

    def test_empty_string(self):
        result = mask_pii("")
        assert result == ""

    def test_short_value(self):
        result = mask_pii("ab", keep_last=4)
        assert result == "**"


class TestSanitizeFieldName:
    """Test field name sanitization."""

    def test_normal_name(self):
        assert sanitize_field_name("user_email") == "user_email"

    def test_special_chars(self):
        result = sanitize_field_name("user@email#field")
        assert result == "user_email_field"

    def test_dots_preserved(self):
        assert sanitize_field_name("user.email") == "user.email"
