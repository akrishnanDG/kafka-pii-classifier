"""Tests for SchemaTagger."""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.pii.types import PIIType
from src.pii.classifier import FieldClassification
from src.schema_registry.tagger import SchemaTagger
from src.utils.exceptions import TaggingError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_classification(
    field_path='user.email',
    pii_types=None,
    tags=None,
    confidence=0.95,
    detection_count=5,
    total_samples=10,
    detection_rate=0.5,
):
    """Build a FieldClassification with sensible defaults."""
    return FieldClassification(
        field_path=field_path,
        pii_types=pii_types or {PIIType.EMAIL},
        tags=tags or ['PII', 'PII-Email'],
        confidence=confidence,
        detection_count=detection_count,
        total_samples=total_samples,
        detection_rate=detection_rate,
    )


def _tagger_config(**overrides):
    cfg = {
        'enabled': True,
        'tag_format': 'metadata',
        'dual_tagging': True,
        'create_backup': False,
    }
    cfg.update(overrides)
    return cfg


def _make_tagger(config=None, sr_client=None):
    """Build a SchemaTagger with a mock schema registry client."""
    return SchemaTagger(
        schema_registry_client=sr_client or MagicMock(),
        config=config or _tagger_config(),
    )


# ===================================================================
# tag_schema returns early when disabled
# ===================================================================

class TestTagSchemaDisabled:
    """tag_schema returns early when disabled."""

    def test_returns_without_tagging_when_disabled(self):
        tagger = _make_tagger(config=_tagger_config(enabled=False))
        classifications = {'email': _make_classification()}

        result = tagger.tag_schema('my-topic-value', classifications)

        assert result['success'] is False
        assert result['fields_tagged'] == 0
        assert result['metadata_applied'] is False

    def test_does_not_call_schema_registry_when_disabled(self):
        mock_sr = MagicMock()
        tagger = _make_tagger(
            config=_tagger_config(enabled=False),
            sr_client=mock_sr,
        )
        classifications = {'email': _make_classification()}

        tagger.tag_schema('subj', classifications)

        mock_sr.get_schema.assert_not_called()
        mock_sr.register_schema.assert_not_called()


# ===================================================================
# tag_schema returns early with no classifications
# ===================================================================

class TestTagSchemaNoClassifications:
    """tag_schema returns early with no classifications."""

    def test_returns_without_tagging_when_empty_dict(self):
        tagger = _make_tagger(config=_tagger_config(enabled=True))
        result = tagger.tag_schema('subj', {})

        assert result['success'] is False
        assert result['fields_tagged'] == 0

    def test_returns_without_tagging_when_none_like(self):
        """Even if enabled, empty classifications should be a no-op."""
        mock_sr = MagicMock()
        tagger = _make_tagger(
            config=_tagger_config(enabled=True),
            sr_client=mock_sr,
        )
        result = tagger.tag_schema('subj', {}, schema_info={'schema': '{}'})

        assert result['fields_tagged'] == 0
        mock_sr.register_schema.assert_not_called()


# ===================================================================
# _parse_avro_schema handles string, dict, and Schema objects
# ===================================================================

class TestParseAvroSchema:
    """_parse_avro_schema handles string, dict, and Schema objects."""

    def test_parses_json_string(self):
        schema_json = json.dumps({
            'type': 'record',
            'name': 'Test',
            'fields': [{'name': 'id', 'type': 'int'}],
        })
        result = SchemaTagger._parse_avro_schema({'schema': schema_json})

        assert isinstance(result, dict)
        assert result['type'] == 'record'
        assert result['name'] == 'Test'

    def test_returns_dict_directly(self):
        schema_dict = {
            'type': 'record',
            'name': 'Test',
            'fields': [{'name': 'id', 'type': 'int'}],
        }
        result = SchemaTagger._parse_avro_schema({'schema': schema_dict})

        assert result is schema_dict
        assert result['type'] == 'record'

    def test_handles_schema_object_with_schema_str(self):
        """Confluent Schema objects have a .schema_str attribute."""
        mock_schema_obj = MagicMock()
        mock_schema_obj.schema_str = json.dumps({
            'type': 'record',
            'name': 'FromObj',
            'fields': [],
        })

        result = SchemaTagger._parse_avro_schema({'schema': mock_schema_obj})

        assert isinstance(result, dict)
        assert result['name'] == 'FromObj'

    def test_raises_tagging_error_for_missing_schema_key(self):
        with pytest.raises(TaggingError, match="does not contain a 'schema' key"):
            SchemaTagger._parse_avro_schema({})

    def test_raises_tagging_error_for_invalid_json(self):
        with pytest.raises(TaggingError, match='Failed to parse AVRO schema JSON'):
            SchemaTagger._parse_avro_schema({'schema': 'not valid json {'})


# ===================================================================
# _build_doc_annotation format
# ===================================================================

class TestBuildDocAnnotation:
    """_build_doc_annotation format."""

    def test_format_single_type(self):
        cls = _make_classification(
            pii_types={PIIType.EMAIL},
            confidence=0.95,
        )
        doc = SchemaTagger._build_doc_annotation(cls)

        assert doc == 'PII: EMAIL (confidence: 0.95)'

    def test_format_multiple_types_sorted(self):
        cls = _make_classification(
            pii_types={PIIType.SSN, PIIType.EMAIL},
            confidence=0.88,
        )
        doc = SchemaTagger._build_doc_annotation(cls)

        # Types should be sorted alphabetically
        assert doc == 'PII: EMAIL, SSN (confidence: 0.88)'

    def test_confidence_formatted_to_two_decimals(self):
        cls = _make_classification(confidence=0.9)
        doc = SchemaTagger._build_doc_annotation(cls)

        assert '(confidence: 0.90)' in doc

    @pytest.mark.parametrize(
        'pii_type,expected_name',
        [
            (PIIType.CREDIT_CARD, 'CREDIT_CARD'),
            (PIIType.PHONE_NUMBER, 'PHONE_NUMBER'),
            (PIIType.DATE_OF_BIRTH, 'DATE_OF_BIRTH'),
            (PIIType.IP_ADDRESS, 'IP_ADDRESS'),
        ],
    )
    def test_uses_enum_value_in_doc(self, pii_type, expected_name):
        cls = _make_classification(pii_types={pii_type}, confidence=0.99)
        doc = SchemaTagger._build_doc_annotation(cls)

        assert expected_name in doc


# ===================================================================
# _tag_fields_recursive tags correct fields
# ===================================================================

class TestTagFieldsRecursive:
    """_tag_fields_recursive tags correct fields."""

    def test_tags_matching_flat_field(self):
        fields = [
            {'name': 'email', 'type': 'string'},
            {'name': 'id', 'type': 'int'},
        ]
        classifications = {
            'email': _make_classification(field_path='email'),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 1
        assert 'doc' in fields[0]
        assert 'PII:' in fields[0]['doc']
        assert 'doc' not in fields[1]

    def test_tags_by_full_dotted_path(self):
        fields = [
            {'name': 'email', 'type': 'string'},
        ]
        classifications = {
            'user.email': _make_classification(field_path='user.email'),
        }

        # With prefix='user', the full path becomes 'user.email'
        count = SchemaTagger._tag_fields_recursive(
            fields, classifications, prefix='user'
        )

        assert count == 1
        assert 'doc' in fields[0]

    def test_does_not_tag_unmatched_fields(self):
        fields = [
            {'name': 'status', 'type': 'string'},
            {'name': 'count', 'type': 'int'},
        ]
        classifications = {
            'email': _make_classification(field_path='email'),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 0
        assert 'doc' not in fields[0]
        assert 'doc' not in fields[1]

    def test_tags_multiple_fields(self):
        fields = [
            {'name': 'email', 'type': 'string'},
            {'name': 'ssn', 'type': 'string'},
            {'name': 'id', 'type': 'int'},
        ]
        classifications = {
            'email': _make_classification(
                field_path='email', pii_types={PIIType.EMAIL}
            ),
            'ssn': _make_classification(
                field_path='ssn', pii_types={PIIType.SSN},
                tags=['PII', 'PII-SSN'],
            ),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 2
        assert 'doc' in fields[0]
        assert 'doc' in fields[1]
        assert 'doc' not in fields[2]


# ===================================================================
# _tag_fields_recursive handles nested records
# ===================================================================

class TestTagFieldsRecursiveNested:
    """_tag_fields_recursive handles nested records."""

    def test_recurses_into_nested_record(self):
        """Fields inside a nested record should be tagged using dotted paths."""
        fields = [
            {
                'name': 'address',
                'type': {
                    'type': 'record',
                    'name': 'Address',
                    'fields': [
                        {'name': 'street', 'type': 'string'},
                        {'name': 'city', 'type': 'string'},
                    ],
                },
            },
        ]
        classifications = {
            'address.street': _make_classification(
                field_path='address.street',
                pii_types={PIIType.ADDRESS},
                tags=['PII', 'PII-Address'],
            ),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 1
        nested_fields = fields[0]['type']['fields']
        assert 'doc' in nested_fields[0]  # street
        assert 'PII:' in nested_fields[0]['doc']
        assert 'doc' not in nested_fields[1]  # city

    def test_recurses_into_union_with_record(self):
        """Union types like ["null", {"type": "record", ...}] should be
        handled correctly."""
        fields = [
            {
                'name': 'contact',
                'type': [
                    'null',
                    {
                        'type': 'record',
                        'name': 'Contact',
                        'fields': [
                            {'name': 'phone', 'type': 'string'},
                        ],
                    },
                ],
            },
        ]
        classifications = {
            'contact.phone': _make_classification(
                field_path='contact.phone',
                pii_types={PIIType.PHONE_NUMBER},
                tags=['PII', 'PII-Phone-Number'],
            ),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 1
        # The phone field inside the union-record should be tagged
        union_record = fields[0]['type'][1]
        assert 'doc' in union_record['fields'][0]

    def test_deeply_nested_records(self):
        """Two levels of nesting: outer.inner.email."""
        fields = [
            {
                'name': 'outer',
                'type': {
                    'type': 'record',
                    'name': 'Outer',
                    'fields': [
                        {
                            'name': 'inner',
                            'type': {
                                'type': 'record',
                                'name': 'Inner',
                                'fields': [
                                    {'name': 'email', 'type': 'string'},
                                ],
                            },
                        },
                    ],
                },
            },
        ]
        classifications = {
            'outer.inner.email': _make_classification(
                field_path='outer.inner.email',
                pii_types={PIIType.EMAIL},
            ),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 1
        deep_field = fields[0]['type']['fields'][0]['type']['fields'][0]
        assert 'doc' in deep_field
        assert 'EMAIL' in deep_field['doc']

    def test_array_items_record(self):
        """Records inside array items should also be recursed into."""
        fields = [
            {
                'name': 'contacts',
                'type': {
                    'type': 'array',
                    'items': {
                        'type': 'record',
                        'name': 'Contact',
                        'fields': [
                            {'name': 'email', 'type': 'string'},
                        ],
                    },
                },
            },
        ]
        classifications = {
            'contacts.email': _make_classification(
                field_path='contacts.email',
                pii_types={PIIType.EMAIL},
            ),
        }

        count = SchemaTagger._tag_fields_recursive(fields, classifications)

        assert count == 1
        item_fields = fields[0]['type']['items']['fields']
        assert 'doc' in item_fields[0]


# ===================================================================
# tag_schema integration with mock SR client
# ===================================================================

class TestTagSchemaIntegration:
    """Integration-style tests with a mocked SchemaRegistryClientWrapper."""

    def test_tag_schema_fetches_schema_when_not_provided(self):
        mock_sr = MagicMock()
        schema_json = json.dumps({
            'type': 'record',
            'name': 'User',
            'fields': [
                {'name': 'email', 'type': 'string'},
            ],
        })
        mock_sr.get_schema.return_value = {
            'schema': schema_json,
            'version': 1,
            'schema_id': 42,
            'schema_type': 'AVRO',
        }
        mock_sr.register_schema.return_value = 43
        mock_sr.get_compatibility.return_value = None
        mock_sr.set_compatibility.return_value = True
        mock_sr.update_schema_metadata.return_value = True

        tagger = _make_tagger(
            config=_tagger_config(enabled=True),
            sr_client=mock_sr,
        )
        classifications = {
            'email': _make_classification(field_path='email'),
        }

        result = tagger.tag_schema('user-value', classifications, schema_info=None)

        # get_schema is called once to fetch the schema and once more after
        # registration to retrieve the new version number.
        assert mock_sr.get_schema.call_count >= 1
        # The first call must be with the subject to fetch the schema
        mock_sr.get_schema.assert_any_call('user-value')
        assert result['fields_tagged'] == 1

    def test_tag_schema_uses_provided_schema_info(self):
        mock_sr = MagicMock()
        mock_sr.register_schema.return_value = 50
        mock_sr.get_compatibility.return_value = None
        mock_sr.set_compatibility.return_value = True
        mock_sr.update_schema_metadata.return_value = True
        # After registration, _tag_with_metadata calls get_schema again
        # to retrieve the new version number -- provide a return value for that.
        mock_sr.get_schema.return_value = {
            'version': 2,
            'schema_id': 50,
        }

        tagger = _make_tagger(
            config=_tagger_config(enabled=True),
            sr_client=mock_sr,
        )

        schema_info = {
            'schema': json.dumps({
                'type': 'record',
                'name': 'User',
                'fields': [{'name': 'email', 'type': 'string'}],
            }),
            'version': 1,
            'schema_id': 42,
            'schema_type': 'AVRO',
        }
        classifications = {
            'email': _make_classification(field_path='email'),
        }

        result = tagger.tag_schema('user-value', classifications, schema_info)

        # get_schema should only be called AFTER registration (to fetch the
        # new version), not before (because schema_info was provided).
        # The first call should not be to look up the schema.
        assert result['fields_tagged'] == 1
        assert result['success'] is True
        # register_schema must have been called
        mock_sr.register_schema.assert_called_once()
