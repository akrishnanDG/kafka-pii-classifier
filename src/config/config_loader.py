"""Configuration loader and validator."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv

from ..utils.exceptions import ConfigurationError

# Load environment variables
load_dotenv()


class ConfigLoader:
    """Load and validate configuration from YAML files and environment variables."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration loader.
        
        Args:
            config_path: Path to configuration YAML file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
    
    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file and environment variables.
        
        Returns:
            Loaded configuration dictionary
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if not self.config_path:
            raise ConfigurationError("Configuration path not provided")
        
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        # Load YAML file
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse YAML configuration: {e}")
        
        # Override with environment variables (includes ${VAR} substitution)
        self._override_with_env()
        
        # Remove None values (optional env vars not set)
        self._remove_none_values()
        
        # Validate configuration
        self._validate()
        
        return self.config
    
    def _remove_none_values(self):
        """Remove None values from config (optional env vars not set)."""
        if isinstance(self.config, dict):
            keys_to_remove = [k for k, v in self.config.items() if v is None]
            for k in keys_to_remove:
                del self.config[k]
            # Recursively process nested dicts
            for v in self.config.values():
                if isinstance(v, dict):
                    self._remove_none_values_from_dict(v)
    
    def _remove_none_values_from_dict(self, d: dict):
        """Recursively remove None values from a dictionary."""
        keys_to_remove = [k for k, v in d.items() if v is None]
        for k in keys_to_remove:
            del d[k]
        for v in d.values():
            if isinstance(v, dict):
                self._remove_none_values_from_dict(v)
    
    def _substitute_env_vars(self, value: Any) -> Any:
        """
        Substitute environment variables in config values.
        Supports ${VAR} and ${?VAR} syntax.
        
        Args:
            value: Config value that may contain env var references
        
        Returns:
            Value with env vars substituted
        """
        if isinstance(value, str):
            # Handle ${VAR} or ${?VAR} syntax
            if value.startswith("${") and value.endswith("}"):
                env_var = value[2:-1].strip()
                optional = env_var.startswith("?")
                if optional:
                    env_var = env_var[1:]
                
                # Remove quotes if present
                env_var = env_var.strip('"').strip("'")
                
                env_value = os.getenv(env_var)
                if env_value:
                    return env_value
                elif optional:
                    return None  # Optional var not set
                else:
                    raise ConfigurationError(f"Required environment variable not set: {env_var}")
        
        elif isinstance(value, dict):
            return {k: self._substitute_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._substitute_env_vars(item) for item in value]
        
        return value
    
    def _override_with_env(self):
        """Override configuration values with environment variables (optional overrides only)."""
        # Substitute ${VAR} syntax in config (for optional env var support)
        self.config = self._substitute_env_vars(self.config)
        
        # Optional: Allow environment variables to override config values
        # (Only if explicitly set - config file takes precedence)
        if os.getenv("KAFKA_BOOTSTRAP_SERVERS"):
            self._set_nested("kafka.bootstrap_servers", os.getenv("KAFKA_BOOTSTRAP_SERVERS"))
        if os.getenv("KAFKA_SECURITY_PROTOCOL"):
            self._set_nested("kafka.security_protocol", os.getenv("KAFKA_SECURITY_PROTOCOL"))
        # Note: We don't override credentials from env vars - keep them in config file
        if os.getenv("KAFKA_GROUP_ID"):
            self._set_nested("kafka.group_id", os.getenv("KAFKA_GROUP_ID"))
        
        # Schema Registry settings (optional overrides)
        if os.getenv("SCHEMA_REGISTRY_URL"):
            self._set_nested("schema_registry.url", os.getenv("SCHEMA_REGISTRY_URL"))
        # Note: We don't override credentials from env vars - keep them in config file
    
    def _set_nested(self, key_path: str, value: Any):
        """Set nested dictionary value using dot notation."""
        keys = key_path.split('.')
        d = self.config
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
    
    def _validate(self):
        """Validate configuration."""
        required_keys = [
            "kafka.bootstrap_servers",
            "schema_registry.url",
        ]
        
        for key_path in required_keys:
            keys = key_path.split('.')
            value = self.config
            try:
                for key in keys:
                    value = value[key]
            except (KeyError, TypeError):
                raise ConfigurationError(f"Missing required configuration: {key_path}")
            
            if not value:
                raise ConfigurationError(f"Empty required configuration: {key_path}")


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Convenience function to load configuration.
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Loaded configuration dictionary
    """
    loader = ConfigLoader(config_path)
    return loader.load()

