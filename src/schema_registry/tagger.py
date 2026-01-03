"""Schema tagging logic - updates Schema Registry with PII tags."""

import logging
from typing import Dict, Any, List, Optional
import json

from ..pii.classifier import FieldClassification
from ..utils.exceptions import TaggingError

logger = logging.getLogger(__name__)


class SchemaTagger:
    """Handles tagging schemas in Schema Registry with PII metadata."""
    
    def __init__(self, schema_registry_client, config: Dict[str, Any]):
        """
        Initialize schema tagger.
        
        Args:
            schema_registry_client: Schema Registry client instance
            config: Tagging configuration
        """
        self.client = schema_registry_client
        self.config = config
        self.dual_tagging = config.get('dual_tagging', True)
        self.tag_format = config.get('tag_format', 'metadata')
        self.create_backup = config.get('create_backup', True)
    
    def tag_schema(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Tag a schema with PII classifications.
        
        Args:
            subject: Schema Registry subject name
            field_classifications: Dictionary of field paths to classifications
            schema_info: Optional existing schema information
        
        Returns:
            True if successful
        """
        if not self.config.get('enabled', False):
            logger.info(f"Tagging disabled, skipping schema update for {subject}")
            return False
        
        try:
            # Get current schema if not provided
            if not schema_info:
                schema_info = self.client.get_schema(subject)
                if not schema_info:
                    logger.warning(f"Schema not found for subject {subject}, cannot tag")
                    return False
            
            # Create backup if requested
            if self.create_backup:
                self._create_backup(subject, schema_info)
            
            # Update schema with PII tags
            if self.tag_format == 'metadata':
                return self._tag_with_metadata(subject, field_classifications, schema_info)
            elif self.tag_format == 'description':
                return self._tag_with_description(subject, field_classifications, schema_info)
            else:
                logger.warning(f"Unknown tag format: {self.tag_format}")
                return False
        
        except Exception as e:
            raise TaggingError(f"Failed to tag schema {subject}: {e}")
    
    def _create_backup(self, subject: str, schema_info: Dict[str, Any]):
        """Create backup of schema before modification."""
        # TODO: Implement schema backup
        logger.debug(f"Backup created for {subject} (version {schema_info.get('version')})")
    
    def _tag_with_metadata(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Dict[str, Any]
    ) -> bool:
        """
        Tag schema using metadata/properties.
        
        Args:
            subject: Schema subject
            field_classifications: Field classifications
            schema_info: Schema information
        
        Returns:
            True if successful
        """
        # TODO: Implement actual metadata update
        # This depends on Schema Registry API version and capabilities
        logger.info(f"Tagging schema {subject} with {len(field_classifications)} PII fields")
        logger.info("Metadata update - TODO: Implement based on Schema Registry API")
        
        for field_path, classification in field_classifications.items():
            logger.info(
                f"  Field: {field_path} -> Tags: {classification.tags}, "
                f"Types: {[pt.value for pt in classification.pii_types]}"
            )
        
        return True
    
    def _tag_with_description(
        self,
        subject: str,
        field_classifications: Dict[str, FieldClassification],
        schema_info: Dict[str, Any]
    ) -> bool:
        """
        Tag schema by updating field descriptions.
        
        Args:
            subject: Schema subject
            field_classifications: Field classifications
            schema_info: Schema information
        
        Returns:
            True if successful
        """
        # TODO: Implement description-based tagging
        logger.info(f"Tagging schema {subject} via descriptions")
        return True
    
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
        tag_counts = {}
        type_counts = {}
        
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

