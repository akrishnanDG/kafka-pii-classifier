"""Deserializers for Schema Registry messages using Confluent's provided SerDes."""

import logging
from typing import Optional, Dict, Any
from confluent_kafka.schema_registry import SchemaRegistryClient

logger = logging.getLogger(__name__)

# Try to import Confluent's Avro deserializer
try:
    from confluent_kafka.schema_registry.avro import AvroDeserializer
    AVRO_DESERIALIZER_AVAILABLE = True
except ImportError:
    AVRO_DESERIALIZER_AVAILABLE = False
    logger.warning("confluent-kafka AvroDeserializer not available - Avro deserialization will be disabled")

# Try to import Confluent's Protobuf deserializer
try:
    from confluent_kafka.schema_registry.protobuf import ProtobufDeserializer
    PROTOBUF_DESERIALIZER_AVAILABLE = True
except ImportError:
    PROTOBUF_DESERIALIZER_AVAILABLE = False
    logger.warning("confluent-kafka ProtobufDeserializer not available - Protobuf deserialization will be disabled")

# Try to import Confluent's JSON Schema deserializer
try:
    from confluent_kafka.schema_registry.json_schema import JSONDeserializer
    JSON_DESERIALIZER_AVAILABLE = True
except ImportError:
    JSON_DESERIALIZER_AVAILABLE = False
    logger.warning("confluent-kafka JSONDeserializer not available - JSON Schema deserialization will be disabled")


def deserialize_message(
    value: bytes,
    schema_registry_client: SchemaRegistryClient,
    schema_type: Optional[str] = None,
    subject: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Deserialize message using Confluent's provided deserializers.
    
    Args:
        value: Message value bytes
        schema_registry_client: Schema Registry client
        schema_type: Schema type (AVRO, PROTOBUF, JSON) - auto-detected if None
        subject: Optional subject name for schema lookup
        
    Returns:
        Deserialized data as dict or None if deserialization fails
    """
    if not value:
        return None
    
    # Check if message has Schema Registry wire format (magic byte + schema ID)
    if len(value) < 5 or value[0] != 0x00:
        # Not Schema Registry format - try JSON parsing
        from .helpers import safe_json_parse
        return safe_json_parse(value)
    
    # Determine schema type if not provided
    if schema_type is None and subject:
        try:
            schema_info = schema_registry_client.get_latest_version(subject)
            if schema_info and hasattr(schema_info, 'schema_type'):
                schema_type = schema_info.schema_type
            else:
                # Try to infer from subject or default to AVRO
                schema_type = 'AVRO'
        except Exception as e:
            logger.debug(f"Could not determine schema type for subject {subject}: {e}")
            schema_type = 'AVRO'  # Default
    
    # Use appropriate Confluent deserializer
    try:
        if schema_type and schema_type.upper() == 'AVRO' and AVRO_DESERIALIZER_AVAILABLE:
            # AvroDeserializer expects a dict or a specific reader schema
            # For auto-detection, we'll use None as reader schema (uses writer schema)
            deserializer = AvroDeserializer(schema_registry_client, schema_str=None)
            deserialized = deserializer(value, None)
            
            # Convert to dict if needed
            if isinstance(deserialized, dict):
                return deserialized
            else:
                # Avro records should be dicts, but handle other types
                return {'value': deserialized}
        
        elif schema_type and schema_type.upper() == 'PROTOBUF' and PROTOBUF_DESERIALIZER_AVAILABLE:
            # ProtobufDeserializer requires a message class
            # For now, we'll need the message class or use a different approach
            logger.debug("Protobuf deserialization requires message class - not yet implemented")
            # Fallback to JSON parsing
            from .helpers import safe_json_parse
            return safe_json_parse(value)
        
        elif schema_type and (schema_type.upper() == 'JSON' or schema_type.upper() == 'JSONSCHEMA') and JSON_DESERIALIZER_AVAILABLE:
            # JSONDeserializer expects a JSON schema string
            # For auto-detection, we'll use None and let it use the schema from the message
            deserializer = JSONDeserializer(schema_registry_client, schema_str=None)
            deserialized = deserializer(value, None)
            
            # Convert to dict if needed
            if isinstance(deserialized, dict):
                return deserialized
            else:
                return {'value': deserialized}
        
        else:
            # Unknown schema type or deserializer not available - try Avro as default
            if AVRO_DESERIALIZER_AVAILABLE:
                try:
                    deserializer = AvroDeserializer(schema_registry_client, schema_str=None)
                    deserialized = deserializer(value, None)
                    if isinstance(deserialized, dict):
                        return deserialized
                    else:
                        return {'value': deserialized}
                except Exception as e:
                    logger.debug(f"Avro deserialization failed: {e}, trying JSON fallback")
            
            # Fallback to JSON parsing
            from .helpers import safe_json_parse
            return safe_json_parse(value)
            
    except Exception as e:
        logger.debug(f"Failed to deserialize message with Confluent deserializer: {e}")
        # Fallback to JSON parsing
        from .helpers import safe_json_parse
        return safe_json_parse(value)
