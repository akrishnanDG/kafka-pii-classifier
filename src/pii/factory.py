"""Factory for creating PII detector providers."""

import logging
from typing import Dict, Any, Optional, List
from .base_detector import PIIDetectorBase
from .pattern_detector import PatternDetector
from .presidio_detector import PresidioDetector

# Optional cloud providers - import only if available
try:
    from .aws_detector import AWSComprehendDetector
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from .gcp_detector import GCPDLPDetector
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

try:
    from .azure_detector import AzureTextAnalyticsDetector
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from .ollama_detector import OllamaDetector
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    from .llm_agent import SchemaAwareLLMDetector
    LLM_AGENT_AVAILABLE = True
except ImportError:
    LLM_AGENT_AVAILABLE = False

logger = logging.getLogger(__name__)


class PIIDetectorFactory:
    """Factory for creating PII detector instances."""
    
    _providers: Dict[str, type] = {}
    
    @classmethod
    def register_provider(cls, name: str, provider_class: type):
        """
        Register a PII detector provider.
        
        Args:
            name: Provider name (e.g., "presidio", "aws", "gcp", "azure")
            provider_class: Provider class that implements PIIDetectorBase
        """
        if not issubclass(provider_class, PIIDetectorBase):
            raise ValueError(f"Provider class must implement PIIDetectorBase")
        cls._providers[name.lower()] = provider_class
        logger.debug(f"Registered PII detector provider: {name}")
    
    @classmethod
    def create(cls, provider_name: str, config: Dict[str, Any]) -> PIIDetectorBase:
        """
        Create a PII detector instance.
        
        Args:
            provider_name: Name of the provider (e.g., "presidio", "aws", "gcp", "azure", "pattern")
            config: Configuration dictionary for the detector
        
        Returns:
            PIIDetectorBase instance
        
        Raises:
            ValueError: If provider is not registered
        """
        provider_name = provider_name.lower()
        
        if provider_name not in cls._providers:
            available = ", ".join(cls._providers.keys())
            raise ValueError(
                f"Unknown PII detector provider: {provider_name}. "
                f"Available providers: {available}"
            )
        
        provider_class = cls._providers[provider_name]
        
        try:
            # Extract provider-specific config from providers_config or providers key
            providers_config = config.get('providers_config', config.get('providers', {}))
            if isinstance(providers_config, dict):
                provider_config = providers_config.get(provider_name, {})
            else:
                provider_config = {}
            # Merge with general config
            merged_config = {**config, **provider_config}
            
            instance = provider_class(merged_config)
            logger.info(f"Created PII detector: {provider_name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to create {provider_name} detector: {e}")
            raise
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """
        Get list of available provider names.
        
        Returns:
            List of provider names
        """
        return list(cls._providers.keys())


# Register built-in providers
PIIDetectorFactory.register_provider("pattern", PatternDetector)
PIIDetectorFactory.register_provider("presidio", PresidioDetector)

# Register cloud providers if available
if AWS_AVAILABLE:
    PIIDetectorFactory.register_provider("aws", AWSComprehendDetector)
    PIIDetectorFactory.register_provider("comprehend", AWSComprehendDetector)  # Alias

if GCP_AVAILABLE:
    PIIDetectorFactory.register_provider("gcp", GCPDLPDetector)
    PIIDetectorFactory.register_provider("dlp", GCPDLPDetector)  # Alias

if AZURE_AVAILABLE:
    PIIDetectorFactory.register_provider("azure", AzureTextAnalyticsDetector)

if OLLAMA_AVAILABLE:
    PIIDetectorFactory.register_provider("ollama", OllamaDetector)

if LLM_AGENT_AVAILABLE:
    PIIDetectorFactory.register_provider("llm_agent", SchemaAwareLLMDetector)

