"""Test Kafka and Schema Registry connections.

These tests require a live Kafka cluster and Schema Registry.
Run with: pytest tests/test_connections.py -m integration
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.config_loader import load_config
from src.kafka.consumer import KafkaConsumerService
from src.schema_registry.client import SchemaRegistryClientWrapper
from src.utils.exceptions import KafkaConnectionError, SchemaRegistryError


@pytest.fixture
def config():
    """Load test configuration."""
    paths = [
        Path('config/config.yaml'),
        Path('config/config.test.yaml'),
        Path('config/config.yaml.example'),
    ]
    for p in paths:
        if p.exists():
            return load_config(p)
    pytest.skip("No configuration file found")


@pytest.mark.integration
class TestKafkaConnection:
    """Test Kafka connection (requires live Kafka)."""

    def test_kafka_connect(self, config):
        """Test Kafka connection succeeds."""
        kafka_config = config['kafka']
        consumer = KafkaConsumerService(kafka_config)
        try:
            consumer.connect()
        except KafkaConnectionError:
            pytest.skip("Kafka not available")

    def test_kafka_list_topics(self, config):
        """Test listing Kafka topics."""
        kafka_config = config['kafka']
        consumer = KafkaConsumerService(kafka_config)
        try:
            consumer.connect()
        except KafkaConnectionError:
            pytest.skip("Kafka not available")

        topics = consumer.list_topics()
        assert isinstance(topics, list)
        consumer.disconnect()


@pytest.mark.integration
class TestSchemaRegistryConnection:
    """Test Schema Registry connection (requires live SR)."""

    def test_schema_registry_connect(self, config):
        """Test Schema Registry connection succeeds."""
        sr_config = config['schema_registry']
        client = SchemaRegistryClientWrapper(sr_config)
        try:
            client.connect()
        except SchemaRegistryError:
            pytest.skip("Schema Registry not available")

    def test_schema_registry_list_subjects(self, config):
        """Test listing Schema Registry subjects."""
        sr_config = config['schema_registry']
        client = SchemaRegistryClientWrapper(sr_config)
        try:
            client.connect()
        except SchemaRegistryError:
            pytest.skip("Schema Registry not available")

        subjects = client.list_subjects()
        assert isinstance(subjects, list)
