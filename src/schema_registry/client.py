"""Schema Registry client."""

import logging
from typing import Dict, Any, Optional, List
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.schema_registry_client import Schema

from ..utils.exceptions import SchemaRegistryError

logger = logging.getLogger(__name__)


class SchemaRegistryClientWrapper:
    """Wrapper for Schema Registry client operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Schema Registry client.
        
        Args:
            config: Schema Registry configuration
        """
        self.config = config
        self.client: Optional[SchemaRegistryClient] = None
    
    def connect(self):
        """Connect to Schema Registry."""
        try:
            client_config = {
                'url': self.config['url']
            }
            
            # Handle authentication
            if self.config.get('api_key'):
                api_key = self.config['api_key']
                api_secret = self.config.get('api_secret', '')
                
                # For Confluent Cloud, use basic.auth.user.info
                if api_secret:
                    client_config['basic.auth.user.info'] = f"{api_key}:{api_secret}"
                else:
                    # If only API key provided, use it as basic auth
                    client_config['basic.auth.user.info'] = f"{api_key}:"
            
            self.client = SchemaRegistryClient(client_config)
            logger.info(f"Connected to Schema Registry: {self.config['url']}")
        except Exception as e:
            raise SchemaRegistryError(f"Failed to connect to Schema Registry: {e}")
    
    def get_schema_by_id(self, schema_id: int) -> Optional[Dict[str, Any]]:
        """
        Get schema by schema ID.
        
        Args:
            schema_id: Schema ID
        
        Returns:
            Schema dictionary or None if not found
        """
        if not self.client:
            self.connect()
        
        try:
            schema = self.client.get_schema(schema_id)
            
            # Build schema dict
            schema_dict = {
                'schema_id': schema.schema_id,
                'schema': schema.schema,
            }
            
            # Try to get schema type
            try:
                if hasattr(schema, 'schema_type'):
                    schema_dict['schema_type'] = schema.schema_type
                else:
                    schema_dict['schema_type'] = 'AVRO'  # Default
            except Exception:
                schema_dict['schema_type'] = 'AVRO'
            
            return schema_dict
        except Exception as e:
            error_str = str(e)
            if '404' in error_str or 'not found' in error_str.lower():
                logger.debug(f"Schema ID {schema_id} not found in Schema Registry")
            else:
                logger.warning(f"Error getting schema by ID {schema_id}: {e}")
            return None
    
    def get_schema(self, subject: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Get schema for a subject.
        
        Args:
            subject: Schema subject name
            version: Optional schema version (latest if not specified)
        
        Returns:
            Schema dictionary or None if not found
        """
        if not self.client:
            self.connect()
        
        try:
            if version:
                schema = self.client.get_version(subject, version)
            else:
                schema = self.client.get_latest_version(subject)
            
            # Build schema dict, handling missing attributes gracefully
            schema_dict = {
                'subject': schema.subject,
                'version': schema.version,
                'schema_id': schema.schema_id,
                'schema': schema.schema,
            }
            
            # schema_type may not be available in all versions - handle gracefully
            try:
                if hasattr(schema, 'schema_type'):
                    schema_dict['schema_type'] = schema.schema_type
                else:
                    # Try to infer from schema content or default
                    schema_dict['schema_type'] = 'AVRO'  # Default assumption
            except Exception as e:
                logger.debug(f"Could not determine schema_type for {subject}: {e}")
                schema_dict['schema_type'] = 'AVRO'  # Default assumption
            
            return schema_dict
        except Exception as e:
            # Check if it's a 404 (not found) vs other error
            error_str = str(e)
            if '404' in error_str or 'not found' in error_str.lower():
                # Subject doesn't exist - this is expected for schemaless topics
                logger.debug(f"Subject {subject} not found in Schema Registry")
            else:
                # Other error - log it but don't fail
                logger.warning(f"Error getting schema for subject {subject}: {e}")
            return None
    
    def schema_exists(self, subject: str) -> bool:
        """
        Check if schema exists for subject.
        
        Args:
            subject: Schema subject name
        
        Returns:
            True if schema exists
        """
        return self.get_schema(subject) is not None
    
    def list_subjects(self) -> List[str]:
        """
        List all subjects.
        
        Returns:
            List of subject names
        """
        if not self.client:
            self.connect()
        
        try:
            return self.client.get_subjects()
        except Exception as e:
            raise SchemaRegistryError(f"Failed to list subjects: {e}")
    
    def register_schema(self, subject: str, schema_str: str, schema_type: str = "JSON") -> int:
        """
        Register a new schema.
        
        Args:
            subject: Schema subject name
            schema_str: Schema definition as string
            schema_type: Schema type (JSON, AVRO, PROTOBUF)
        
        Returns:
            Schema ID
        """
        if not self.client:
            self.connect()
        
        try:
            schema = Schema(schema_str, schema_type=schema_type)
            schema_id = self.client.register_schema(subject, schema)
            logger.info(f"Registered schema for subject {subject} with ID {schema_id}")
            return schema_id
        except Exception as e:
            raise SchemaRegistryError(f"Failed to register schema for {subject}: {e}")
    
    def update_schema_metadata(self, subject: str, metadata: Dict[str, Any]) -> bool:
        """
        Update schema metadata (tags, properties).
        
        Note: This is a placeholder - actual implementation depends on
        Schema Registry API version and capabilities.
        
        Args:
            subject: Schema subject name
            metadata: Metadata to update
        
        Returns:
            True if successful
        """
        # TODO: Implement actual metadata update based on Schema Registry API
        logger.warning("Schema metadata update not yet implemented")
        return False

