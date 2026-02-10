"""Schema tagging logic - updates Schema Registry with PII tags."""

import copy
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from ..pii.classifier import FieldClassification
from ..utils.exceptions import TaggingError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default directory for local schema backups
# ---------------------------------------------------------------------------
_DEFAULT_BACKUP_DIR = "schema_backups"


class SchemaTagger:
    """Handles tagging schemas in Schema Registry with PII metadata."""

    def __init__(self, schema_registry_client, config: Dict[str, Any]):
        """
        Initialize schema tagger.

        Args:
            schema_registry_client: Schema Registry client instance
                (SchemaRegistryClientWrapper)
            config: Tagging configuration
        """
        self.client = schema_registry_client
        self.config = config
        self.dual_tagging = config.get('dual_tagging', True)
        self.tag_format = config.get('tag_format', 'metadata')
        self.create_backup = config.get('create_backup', True)
        self.backup_dir = Path(config.get('backup_dir', _DEFAULT_BACKUP_DIR))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def tag_schema(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Tag a schema with PII classifications.

        Args:
            subject: Schema Registry subject name
            field_classifications: Dictionary of field paths to classifications
            schema_info: Optional existing schema information

        Returns:
            Dict with tagging results::

                {
                    "success": bool,
                    "fields_tagged": int,
                    "schema_version": int | None,
                    "schema_id": int | None,
                    "metadata_applied": bool,
                    "backup_path": str | None,
                    "errors": [str, ...]
                }

        Raises:
            TaggingError: If tagging fails with an unrecoverable error
        """
        result: Dict[str, Any] = {
            'success': False,
            'fields_tagged': 0,
            'schema_version': None,
            'schema_id': None,
            'metadata_applied': False,
            'backup_path': None,
            'errors': [],
        }

        if not self.config.get('enabled', False):
            logger.info(f"Tagging disabled, skipping schema update for {subject}")
            return result

        if not field_classifications:
            logger.info(f"No PII fields to tag for {subject}")
            return result

        try:
            # Get current schema if not provided
            if not schema_info:
                schema_info = self.client.get_schema(subject)
                if not schema_info:
                    msg = f"Schema not found for subject {subject}, cannot tag"
                    logger.warning(msg)
                    result['errors'].append(msg)
                    return result

            # Create backup if requested
            if self.create_backup:
                backup_path = self._create_backup(subject, schema_info)
                result['backup_path'] = str(backup_path) if backup_path else None

            # Update schema with PII tags
            if self.tag_format == 'metadata':
                tag_result = self._tag_with_metadata(
                    subject, field_classifications, schema_info
                )
            elif self.tag_format == 'description':
                tag_result = self._tag_with_description(
                    subject, field_classifications, schema_info
                )
            else:
                msg = f"Unknown tag format: {self.tag_format}"
                logger.warning(msg)
                result['errors'].append(msg)
                return result

            # Merge tag_result into result
            result.update(tag_result)
            return result

        except TaggingError:
            raise
        except Exception as e:
            raise TaggingError(f"Failed to tag schema {subject}: {e}")

    def generate_tags_summary(
        self,
        field_classifications: Dict[str, FieldClassification]
    ) -> Dict[str, Any]:
        """
        Generate summary of tags to be applied.

        Args:
            field_classifications: Field classifications

        Returns:
            Summary dictionary
        """
        tag_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}

        for classification in field_classifications.values():
            for tag in classification.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

            for pii_type in classification.pii_types:
                type_counts[pii_type.value] = type_counts.get(pii_type.value, 0) + 1

        return {
            'total_fields_tagged': len(field_classifications),
            'tag_counts': tag_counts,
            'pii_type_counts': type_counts,
            'fields': {
                field_path: {
                    'tags': classification.tags,
                    'pii_types': [pt.value for pt in classification.pii_types],
                    'confidence': classification.confidence
                }
                for field_path, classification in field_classifications.items()
            }
        }

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def _create_backup(
        self, subject: str, schema_info: Dict[str, Any]
    ) -> Optional[Path]:
        """Create a local JSON backup of a schema before modification.

        Backups are written to ``<backup_dir>/<subject>/v<version>_<timestamp>.json``.

        Args:
            subject: Schema Registry subject name
            schema_info: Schema dict as returned by the client

        Returns:
            Path to the backup file, or None on failure
        """
        try:
            # Build a safe directory name (replace / with _)
            safe_subject = subject.replace('/', '_').replace('\\', '_')
            subject_dir = self.backup_dir / safe_subject
            subject_dir.mkdir(parents=True, exist_ok=True)

            version = schema_info.get('version', 'unknown')
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            filename = f"v{version}_{timestamp}.json"
            backup_path = subject_dir / filename

            # Build backup payload (handle Schema objects)
            raw_schema = schema_info.get('schema')
            if hasattr(raw_schema, 'schema_str'):
                raw_schema = raw_schema.schema_str

            backup_data = {
                'subject': subject,
                'version': version,
                'schema_id': schema_info.get('schema_id'),
                'schema_type': schema_info.get('schema_type', 'AVRO'),
                'schema': raw_schema,
                'backed_up_at': timestamp,
            }

            backup_path.write_text(
                json.dumps(backup_data, indent=2), encoding='utf-8'
            )

            logger.info(
                f"Schema backup saved for {subject} "
                f"(version {version}) at {backup_path}"
            )
            return backup_path

        except Exception as e:
            logger.warning(
                f"Failed to create schema backup for {subject}: {e}. "
                f"Continuing with tagging anyway."
            )
            return None

    # ------------------------------------------------------------------
    # AVRO schema manipulation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_avro_schema(schema_info: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the AVRO schema JSON from a schema_info dict.

        The ``schema`` value coming from the confluent_kafka client is a
        JSON-encoded *string*.  This helper returns it as a dict.

        Args:
            schema_info: Schema dict (must contain ``schema`` key)

        Returns:
            Parsed AVRO schema dict

        Raises:
            TaggingError: If the schema cannot be parsed
        """
        raw_schema = schema_info.get('schema')
        if raw_schema is None:
            raise TaggingError("schema_info does not contain a 'schema' key")

        if isinstance(raw_schema, dict):
            return raw_schema

        # Handle confluent_kafka Schema objects (have .schema_str attribute)
        if hasattr(raw_schema, 'schema_str'):
            raw_schema = raw_schema.schema_str

        try:
            return json.loads(raw_schema)
        except (json.JSONDecodeError, TypeError) as e:
            raise TaggingError(f"Failed to parse AVRO schema JSON: {e}")

    @staticmethod
    def _build_doc_annotation(classification: FieldClassification) -> str:
        """Build a ``doc`` string for a tagged field.

        Format: ``PII: TYPE1, TYPE2 (confidence: 0.95)``

        Args:
            classification: The PII classification for the field

        Returns:
            Human-readable doc string
        """
        pii_names = sorted(pt.value for pt in classification.pii_types)
        conf = f"{classification.confidence:.2f}"
        return f"PII: {', '.join(pii_names)} (confidence: {conf})"

    @classmethod
    def _tag_fields_recursive(
        cls,
        fields: List[Dict[str, Any]],
        classifications: Dict[str, FieldClassification],
        prefix: str = '',
    ) -> int:
        """Walk an AVRO ``fields`` array and annotate PII fields in-place.

        Handles:
        * Flat records (field name lookup)
        * Nested records (field type is a record with its own ``fields``)
        * Union types (``["null", {"type": "record", ...}]``)

        Args:
            fields: The ``fields`` list of an AVRO record schema (mutated)
            classifications: field_path -> FieldClassification mapping
            prefix: Dot-separated prefix for nested field paths

        Returns:
            Number of fields that were annotated in this call
        """
        tagged_count = 0

        for field_def in fields:
            field_name = field_def.get('name', '')
            field_path = f"{prefix}{field_name}" if not prefix else f"{prefix}.{field_name}"

            # --- Check if this field itself needs tagging ---------------
            # Try both the full dotted path and the bare field name.
            classification = classifications.get(field_path) or classifications.get(field_name)
            if classification is not None:
                field_def['doc'] = cls._build_doc_annotation(classification)
                tagged_count += 1

            # --- Recurse into nested records ----------------------------
            field_type = field_def.get('type')
            nested_records = cls._extract_nested_records(field_type)
            for nested_record in nested_records:
                nested_fields = nested_record.get('fields')
                if nested_fields:
                    tagged_count += cls._tag_fields_recursive(
                        nested_fields, classifications, prefix=field_path
                    )

        return tagged_count

    @staticmethod
    def _extract_nested_records(field_type: Any) -> List[Dict[str, Any]]:
        """Extract nested record schemas from a field type definition.

        Handles plain record dicts, union lists (``["null", <record>]``),
        and array/map item types.

        Args:
            field_type: The ``type`` value of a field

        Returns:
            List of record-type dicts found (may be empty)
        """
        records: List[Dict[str, Any]] = []

        if isinstance(field_type, dict):
            avro_type = field_type.get('type')
            if avro_type == 'record':
                records.append(field_type)
            elif avro_type == 'array':
                # Recurse into array items
                items = field_type.get('items')
                if isinstance(items, dict) and items.get('type') == 'record':
                    records.append(items)
            elif avro_type == 'map':
                values = field_type.get('values')
                if isinstance(values, dict) and values.get('type') == 'record':
                    records.append(values)

        elif isinstance(field_type, list):
            # Union type - check each branch
            for branch in field_type:
                if isinstance(branch, dict):
                    records.extend(
                        SchemaTagger._extract_nested_records(branch)
                    )

        return records

    # ------------------------------------------------------------------
    # Compatibility helper
    # ------------------------------------------------------------------

    def _with_relaxed_compatibility(
        self, subject: str, action: callable
    ) -> Any:
        """Execute *action* with the subject's compatibility temporarily set
        to NONE, then restore the original setting.

        If the compatibility API is unavailable the action is still executed
        (adding ``doc`` fields is typically compatible under BACKWARD/FORWARD
        anyway).

        Args:
            subject: Schema Registry subject
            action: Zero-argument callable to execute

        Returns:
            Whatever *action* returns
        """
        original_compat = None
        compat_changed = False

        try:
            # Save current compatibility
            if hasattr(self.client, 'get_compatibility'):
                original_compat = self.client.get_compatibility(subject)

            # Temporarily set to NONE
            if hasattr(self.client, 'set_compatibility'):
                compat_changed = self.client.set_compatibility(subject, 'NONE')
                if compat_changed:
                    logger.debug(
                        f"Temporarily set compatibility for {subject} to NONE "
                        f"(was: {original_compat or 'global default'})"
                    )

            return action()

        finally:
            # Restore original compatibility
            if compat_changed and hasattr(self.client, 'set_compatibility'):
                if original_compat:
                    self.client.set_compatibility(subject, original_compat)
                    logger.debug(
                        f"Restored compatibility for {subject} to {original_compat}"
                    )
                elif hasattr(self.client, 'delete_subject_config'):
                    # No subject-level compat was set before; delete override
                    self.client.delete_subject_config(subject)
                    logger.debug(
                        f"Removed subject-level compatibility override for {subject}"
                    )

    # ------------------------------------------------------------------
    # Tagging strategies
    # ------------------------------------------------------------------

    def _tag_with_metadata(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Tag schema using both doc-field annotations AND the Schema Registry
        subject-level metadata REST API.

        Steps:
        1. Parse the current AVRO schema.
        2. Add ``doc`` annotations to every classified field.
        3. Register the modified schema as a new version (with compatibility
           temporarily relaxed to NONE).
        4. PUT subject-level metadata/tags via the REST API (best-effort;
           gracefully handles SR versions that lack the endpoint).

        Args:
            subject: Schema Registry subject name
            field_classifications: field_path -> FieldClassification
            schema_info: Current schema info dict

        Returns:
            Result dict fragment with keys ``success``, ``fields_tagged``,
            ``schema_version``, ``schema_id``, ``metadata_applied``, ``errors``
        """
        result: Dict[str, Any] = {
            'success': False,
            'fields_tagged': 0,
            'schema_version': None,
            'schema_id': None,
            'metadata_applied': False,
            'errors': [],
        }

        # 1. Parse and deep-copy the schema so we don't mutate the original
        try:
            avro_schema = copy.deepcopy(self._parse_avro_schema(schema_info))
        except TaggingError as e:
            result['errors'].append(str(e))
            return result

        # 2. Add doc annotations
        top_level_fields = avro_schema.get('fields')
        if top_level_fields is None:
            msg = (
                f"AVRO schema for {subject} has no 'fields' key "
                f"(type={avro_schema.get('type')}). Cannot tag."
            )
            logger.warning(msg)
            result['errors'].append(msg)
            return result

        tagged_count = self._tag_fields_recursive(
            top_level_fields, field_classifications
        )
        result['fields_tagged'] = tagged_count

        if tagged_count == 0:
            logger.info(
                f"No matching fields found in schema for {subject} "
                f"(classifications: {list(field_classifications.keys())})"
            )
            result['success'] = True  # Nothing to do is not a failure
            return result

        # 3. Register the modified schema (with relaxed compatibility)
        updated_schema_str = json.dumps(avro_schema, indent=None)
        schema_type = schema_info.get('schema_type', 'AVRO')

        try:
            def _register():
                return self.client.register_schema(
                    subject, updated_schema_str, schema_type=schema_type
                )

            new_schema_id = self._with_relaxed_compatibility(subject, _register)
            result['schema_id'] = new_schema_id
            result['success'] = True

            logger.info(
                f"Registered tagged schema for {subject}: "
                f"{tagged_count} fields annotated, schema_id={new_schema_id}"
            )

            # Fetch the new version number
            try:
                new_info = self.client.get_schema(subject)
                if new_info:
                    result['schema_version'] = new_info.get('version')
            except Exception:
                pass  # Non-critical

        except Exception as e:
            msg = f"Failed to register tagged schema for {subject}: {e}"
            logger.error(msg)
            result['errors'].append(msg)
            return result

        # 4. Set subject-level metadata tags via REST (best-effort)
        try:
            all_tags: Set[str] = set()
            pii_field_names: List[str] = []
            avg_confidence = 0.0

            for field_path, cls in field_classifications.items():
                all_tags.update(cls.tags)
                pii_field_names.append(field_path)
                avg_confidence += cls.confidence

            if field_classifications:
                avg_confidence /= len(field_classifications)

            metadata_payload = {
                'tags': sorted(all_tags),
                'properties': {
                    'pii_fields': ','.join(sorted(pii_field_names)),
                    'classification_confidence': f"{avg_confidence:.2f}",
                    'fields_tagged': str(tagged_count),
                    'tagged_at': datetime.now(timezone.utc).isoformat(),
                },
            }

            if hasattr(self.client, 'update_schema_metadata'):
                result['metadata_applied'] = self.client.update_schema_metadata(
                    subject, metadata_payload
                )
            else:
                logger.debug(
                    "Schema registry client does not support "
                    "update_schema_metadata; skipping REST metadata."
                )
        except Exception as e:
            msg = f"Subject-level metadata update failed for {subject}: {e}"
            logger.warning(msg)
            result['errors'].append(msg)
            # Not a hard failure - doc annotations were already written

        return result

    def _tag_with_description(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Tag schema by updating field ``doc`` descriptions only.

        This is the simpler variant: it adds ``doc`` annotations to AVRO
        fields and registers the modified schema, but does NOT attempt to
        use the Schema Registry metadata REST API.

        Args:
            subject: Schema Registry subject name
            field_classifications: field_path -> FieldClassification
            schema_info: Current schema info dict

        Returns:
            Result dict fragment
        """
        result: Dict[str, Any] = {
            'success': False,
            'fields_tagged': 0,
            'schema_version': None,
            'schema_id': None,
            'metadata_applied': False,
            'errors': [],
        }

        # 1. Parse and deep-copy the schema
        try:
            avro_schema = copy.deepcopy(self._parse_avro_schema(schema_info))
        except TaggingError as e:
            result['errors'].append(str(e))
            return result

        # 2. Add doc annotations
        top_level_fields = avro_schema.get('fields')
        if top_level_fields is None:
            msg = (
                f"AVRO schema for {subject} has no 'fields' key "
                f"(type={avro_schema.get('type')}). Cannot tag."
            )
            logger.warning(msg)
            result['errors'].append(msg)
            return result

        tagged_count = self._tag_fields_recursive(
            top_level_fields, field_classifications
        )
        result['fields_tagged'] = tagged_count

        if tagged_count == 0:
            logger.info(
                f"No matching fields found in schema for {subject} "
                f"(classifications: {list(field_classifications.keys())})"
            )
            result['success'] = True
            return result

        # 3. Register the modified schema (with relaxed compatibility)
        updated_schema_str = json.dumps(avro_schema, indent=None)
        schema_type = schema_info.get('schema_type', 'AVRO')

        try:
            def _register():
                return self.client.register_schema(
                    subject, updated_schema_str, schema_type=schema_type
                )

            new_schema_id = self._with_relaxed_compatibility(subject, _register)
            result['schema_id'] = new_schema_id
            result['success'] = True

            logger.info(
                f"Registered tagged schema (description-only) for {subject}: "
                f"{tagged_count} fields annotated, schema_id={new_schema_id}"
            )

            # Fetch the new version number
            try:
                new_info = self.client.get_schema(subject)
                if new_info:
                    result['schema_version'] = new_info.get('version')
            except Exception:
                pass

        except Exception as e:
            msg = f"Failed to register tagged schema for {subject}: {e}"
            logger.error(msg)
            result['errors'].append(msg)

        return result
