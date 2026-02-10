"""Factory for creating PII detector providers."""

import logging
from threading import Lock
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

try:
    from .cloud_llm_detector import OpenAIDetector, AnthropicDetector, GeminiDetector, VertexAIDetector
    CLOUD_LLM_AVAILABLE = True
except ImportError:
    CLOUD_LLM_AVAILABLE = False

logger = logging.getLogger(__name__)


class PIIDetectorFactory:
    """Factory for creating PII detector instances."""
    
    _providers: Dict[str, type] = {}
    _lock = Lock()

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
        with cls._lock:
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

        with cls._lock:
            providers_snapshot = dict(cls._providers)

        if provider_name not in providers_snapshot:
            available = ", ".join(providers_snapshot.keys())
            raise ValueError(
                f"Unknown PII detector provider: {provider_name}. "
                f"Available providers: {available}"
            )
        
        provider_class = providers_snapshot[provider_name]
        
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
        with cls._lock:
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

if CLOUD_LLM_AVAILABLE:
    PIIDetectorFactory.register_provider("openai", OpenAIDetector)
    PIIDetectorFactory.register_provider("chatgpt", OpenAIDetector)
    PIIDetectorFactory.register_provider("anthropic", AnthropicDetector)
    PIIDetectorFactory.register_provider("claude", AnthropicDetector)
    PIIDetectorFactory.register_provider("gemini", GeminiDetector)
    PIIDetectorFactory.register_provider("vertex_ai", VertexAIDetector)

