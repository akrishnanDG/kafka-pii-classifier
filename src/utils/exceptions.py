"""Custom exceptions for the PII classification agent."""


class PIIClassificationError(Exception):
    """Base exception for PII classification errors."""
    pass


class KafkaConnectionError(PIIClassificationError):
    """Raised when Kafka connection fails."""
    pass


class SchemaRegistryError(PIIClassificationError):
    """Raised when Schema Registry operations fail."""
    pass


class ConfigurationError(PIIClassificationError):
    """Raised when configuration is invalid."""
    pass


class SamplingError(PIIClassificationError):
    """Raised when sampling operations fail."""
    pass


class PIIDetectionError(PIIClassificationError):
    """Raised when PII detection fails."""
    pass


class SchemaInferenceError(PIIClassificationError):
    """Raised when schema inference fails."""
    pass


class TaggingError(PIIClassificationError):
    """Raised when schema tagging fails."""
    pass

