"""Integration tests for agent flow, sampling, and API server."""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestAPIServerImports:
    """Test API server can be imported."""

    def test_api_imports(self):
        """Test API server imports successfully."""
        try:
            from src.integration.api import app, run_api_server
        except ImportError as e:
            if 'flask' in str(e).lower():
                pytest.skip("Flask not installed (optional dependency)")
            raise

        # Check routes exist
        routes = [str(rule) for rule in app.url_map.iter_rules()]
        assert len(routes) > 0, "No routes registered"

    def test_health_endpoint_exists(self):
        """Test health endpoint is registered."""
        try:
            from src.integration.api import app
        except ImportError:
            pytest.skip("Flask not installed")

        rules = {str(rule): rule.methods for rule in app.url_map.iter_rules()}
        assert '/health' in rules, "Health endpoint not found"

    def test_classify_endpoint_exists(self):
        """Test classify endpoint is registered."""
        try:
            from src.integration.api import app
        except ImportError:
            pytest.skip("Flask not installed")

        rules = {str(rule) for rule in app.url_map.iter_rules()}
        assert '/api/v1/classify' in rules, "Classify endpoint not found"


@pytest.mark.integration
class TestAgentInitialization:
    """Test agent initialization (requires config file)."""

    @pytest.fixture
    def config_path(self):
        """Find a valid config file."""
        paths = [
            Path('config/config.yaml'),
            Path('config/config.test.yaml'),
            Path('config/config.yaml.example'),
        ]
        for p in paths:
            if p.exists():
                return p
        pytest.skip("No configuration file found")

    def test_agent_initialization(self, config_path):
        """Test agent can be initialized with config."""
        from src.config.config_loader import load_config
        from src.agent import PIIClassificationAgent

        config = load_config(config_path)
        agent = PIIClassificationAgent(config)

        assert agent.kafka_consumer is not None
        assert agent.schema_registry is not None
        assert agent.pii_detector is not None
        assert agent.field_classifier is not None
