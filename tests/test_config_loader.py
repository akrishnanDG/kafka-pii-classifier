"""Unit tests for configuration loader."""

import os
import pytest
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.config_loader import ConfigLoader, load_config
from src.utils.exceptions import ConfigurationError


class TestConfigLoader:
    """Test configuration loading and validation."""

    def _write_config(self, content: str) -> Path:
        """Write config content to a temp file and return its path."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        f.write(content)
        f.close()
        return Path(f.name)

    def test_load_valid_config(self):
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "localhost:9092"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            config = load_config(config_path)
            assert config['kafka']['bootstrap_servers'] == 'localhost:9092'
            assert config['schema_registry']['url'] == 'http://localhost:8081'
        finally:
            os.unlink(config_path)

    def test_missing_kafka_servers(self):
        config_path = self._write_config("""
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            with pytest.raises(ConfigurationError, match="kafka.bootstrap_servers"):
                load_config(config_path)
        finally:
            os.unlink(config_path)

    def test_missing_schema_registry_url(self):
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "localhost:9092"
""")
        try:
            with pytest.raises(ConfigurationError, match="schema_registry.url"):
                load_config(config_path)
        finally:
            os.unlink(config_path)

    def test_missing_config_file(self):
        with pytest.raises(ConfigurationError, match="not found"):
            load_config(Path('/nonexistent/config.yaml'))

    def test_no_config_path(self):
        with pytest.raises(ConfigurationError, match="not provided"):
            load_config(None)

    def test_defaults_applied(self):
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "localhost:9092"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            config = load_config(config_path)
            assert 'pii_detection' in config
            assert 'sampling' in config
            assert 'tagging' in config
            assert config['tagging']['enabled'] is False
        finally:
            os.unlink(config_path)

    def test_env_var_substitution_full(self):
        os.environ['TEST_BOOTSTRAP'] = 'kafka:9092'
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "${TEST_BOOTSTRAP}"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            config = load_config(config_path)
            assert config['kafka']['bootstrap_servers'] == 'kafka:9092'
        finally:
            os.unlink(config_path)
            del os.environ['TEST_BOOTSTRAP']

    def test_env_var_substitution_partial(self):
        os.environ['TEST_HOST'] = 'myhost'
        os.environ['TEST_PORT'] = '9092'
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "${TEST_HOST}:${TEST_PORT}"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            config = load_config(config_path)
            assert config['kafka']['bootstrap_servers'] == 'myhost:9092'
        finally:
            os.unlink(config_path)
            del os.environ['TEST_HOST']
            del os.environ['TEST_PORT']

    def test_optional_env_var_missing(self):
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "localhost:9092"
  sasl_password: "${?NONEXISTENT_VAR}"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            config = load_config(config_path)
            # Optional var should be removed (None values cleaned)
            assert 'sasl_password' not in config.get('kafka', {})
        finally:
            os.unlink(config_path)

    def test_required_env_var_missing(self):
        config_path = self._write_config("""
kafka:
  bootstrap_servers: "${DEFINITELY_NOT_SET_VAR}"
schema_registry:
  url: "http://localhost:8081"
""")
        try:
            with pytest.raises(ConfigurationError, match="DEFINITELY_NOT_SET_VAR"):
                load_config(config_path)
        finally:
            os.unlink(config_path)
