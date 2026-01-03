#!/usr/bin/env python3
"""Test script to verify Kafka and Schema Registry connections."""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.config_loader import load_config
from src.kafka.consumer import KafkaConsumerService
from src.schema_registry.client import SchemaRegistryClientWrapper
from src.utils.logger import setup_logger
from src.utils.exceptions import KafkaConnectionError, SchemaRegistryError

logger = setup_logger(log_level="INFO")


@pytest.fixture
def config():
    """Load test configuration."""
    config_path = Path('config/config.yaml')
    if not config_path.exists():
        config_path = Path('config/config.test.yaml')
    if not config_path.exists():
        config_path = Path('config/config.yaml.example')
    return load_config(config_path)


@pytest.mark.integration
def test_kafka_connection(config):
    """Test Kafka connection and list topics."""
    print("\n" + "="*60)
    print("Testing Kafka Connection")
    print("="*60)
    
    try:
        kafka_config = config['kafka']
        
        print(f"Bootstrap servers: {kafka_config['bootstrap_servers']}")
        print(f"Security protocol: {kafka_config.get('security_protocol', 'PLAINTEXT')}")
        
        consumer = KafkaConsumerService(kafka_config)
        consumer.connect()
        
        print("✅ Kafka connection successful!")
        
        # List topics
        print("\nListing topics...")
        topics = consumer.list_topics()
        print(f"Found {len(topics)} topics")
        
        if topics:
            print("\nSample topics (first 10):")
            for topic in list(topics)[:10]:
                partition_count = consumer.get_partition_count(topic)
                print(f"  - {topic} ({partition_count} partitions)")
        
        consumer.disconnect()
        return True
        
    except KafkaConnectionError as e:
        print(f"❌ Kafka connection failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


@pytest.mark.integration
def test_schema_registry_connection(config):
    """Test Schema Registry connection."""
    print("\n" + "="*60)
    print("Testing Schema Registry Connection")
    print("="*60)
    
    try:
        sr_config = config['schema_registry']
        print(f"Schema Registry URL: {sr_config['url']}")
        
        client = SchemaRegistryClientWrapper(sr_config)
        client.connect()
        
        print("✅ Schema Registry connection successful!")
        
        # List subjects
        print("\nListing subjects...")
        subjects = client.list_subjects()
        print(f"Found {len(subjects)} subjects")
        
        if subjects:
            print("\nSample subjects (first 10):")
            for subject in list(subjects)[:10]:
                print(f"  - {subject}")
        
        return True
        
    except SchemaRegistryError as e:
        print(f"❌ Schema Registry connection failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def main():
    """Run all connection tests."""
    print("="*60)
    print("Connection Tests")
    print("="*60)
    
    # Try to load config
    config_path = Path('config/config.yaml')
    if not config_path.exists():
        config_path = Path('config/config.test.yaml')
    
    if not config_path.exists():
        print("❌ No configuration file found!")
        print("   Please create config/config.yaml or config/config.test.yaml")
        return
    
    print(f"\nLoading configuration from: {config_path}")
    config = load_config(config_path)
    print("✅ Configuration loaded")
    
    # Run tests
    kafka_ok = test_kafka_connection(config)
    sr_ok = test_schema_registry_connection(config)
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    print(f"Kafka:           {'✅ PASS' if kafka_ok else '❌ FAIL'}")
    print(f"Schema Registry: {'✅ PASS' if sr_ok else '❌ FAIL'}")
    
    if kafka_ok and sr_ok:
        print("\n✅ All connection tests passed!")
        return 0
    else:
        print("\n❌ Some connection tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
