"""Kafka consumer service."""

import logging
from typing import Dict, List, Optional, Any
from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient

from ..utils.exceptions import KafkaConnectionError
from ..utils.logger import setup_logger

logger = logging.getLogger(__name__)


class KafkaConsumerService:
    """Kafka consumer service for reading messages from topics."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Kafka consumer.
        
        Args:
            config: Kafka configuration dictionary
        """
        self.config = config
        self.consumer: Optional[Consumer] = None
        self.admin_client: Optional[AdminClient] = None
        
    def _create_consumer_config(self) -> Dict[str, Any]:
        """Create consumer configuration from config dict."""
        consumer_config = {
            'bootstrap.servers': self.config['bootstrap_servers'],
            'group.id': self.config.get('group_id', 'pii-classification-agent'),
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,  # Manual commit for sampling control
            'session.timeout.ms': 30000,
            'log_level': 0,  # Suppress Kafka client logs (0 = no logs)
        }
        
        # Performance optimizations (librdkafka properties)
        # Note: These are librdkafka-specific properties, not all may be supported
        # by all Kafka client versions. We'll try to set them but won't fail if unsupported.
        if self.config.get('fetch_min_bytes'):
            consumer_config['fetch.min.bytes'] = str(self.config['fetch_min_bytes'])
        if self.config.get('fetch_max_wait_ms'):
            consumer_config['fetch.wait.max.ms'] = str(self.config['fetch_max_wait_ms'])
        # Note: max.poll.records is not a librdkafka property, it's handled by the client library
        # We'll skip it to avoid errors
        
        # Add security settings if provided
        if self.config.get('security_protocol'):
            consumer_config['security.protocol'] = self.config['security_protocol']
            if self.config.get('sasl_mechanism'):
                consumer_config['sasl.mechanism'] = self.config['sasl_mechanism']
            if self.config.get('sasl_username'):
                consumer_config['sasl.username'] = self.config['sasl_username']
            if self.config.get('sasl_password'):
                consumer_config['sasl.password'] = self.config['sasl_password']
        
        return consumer_config
    
    def connect(self):
        """Connect to Kafka cluster."""
        try:
            consumer_config = self._create_consumer_config()
            self.consumer = Consumer(consumer_config)
            
            # Create admin client for topic metadata (suppress logs)
            admin_config = consumer_config.copy()
            admin_config['log_level'] = 0
            self.admin_client = AdminClient(admin_config)
            
            logger.info(f"Connected to Kafka cluster: {self.config['bootstrap_servers']}")
        except KafkaException as e:
            raise KafkaConnectionError(f"Failed to connect to Kafka: {e}")
    
    def disconnect(self):
        """Disconnect from Kafka cluster."""
        if self.consumer:
            self.consumer.close()
            self.consumer = None
            logger.info("Disconnected from Kafka cluster")
    
    def list_topics(self, pattern: Optional[str] = None) -> List[str]:
        """
        List available topics.
        
        Args:
            pattern: Optional regex pattern to filter topics
        
        Returns:
            List of topic names
        """
        if not self.admin_client:
            self.connect()
        
        try:
            metadata = self.admin_client.list_topics(timeout=10)
            topics = list(metadata.topics.keys())
            
            if pattern:
                import re
                regex = re.compile(pattern)
                topics = [t for t in topics if regex.match(t)]
            
            logger.info(f"Found {len(topics)} topics")
            return topics
        except Exception as e:
            raise KafkaConnectionError(f"Failed to list topics: {e}")
    
    def get_partition_count(self, topic: str) -> int:
        """
        Get partition count for a topic.
        
        Args:
            topic: Topic name
        
        Returns:
            Number of partitions
        """
        if not self.admin_client:
            self.connect()
        
        try:
            metadata = self.admin_client.list_topics(timeout=10)
            topic_metadata = metadata.topics.get(topic)
            if not topic_metadata:
                raise KafkaConnectionError(f"Topic not found: {topic}")
            return len(topic_metadata.partitions)
        except Exception as e:
            raise KafkaConnectionError(f"Failed to get partition count for {topic}: {e}")
    
    def is_topic_empty(self, topic: str) -> bool:
        """
        Quickly check if topic is empty by comparing start and end offsets.
        
        Args:
            topic: Topic name
        
        Returns:
            True if topic is empty (no messages)
        """
        if not self.consumer:
            self.connect()
        
        try:
            # Get partition metadata (faster with lower timeout)
            metadata = self.admin_client.list_topics(timeout=5)
            topic_metadata = metadata.topics.get(topic)
            if not topic_metadata:
                return True
            
            # Check each partition (with reduced timeout)
            from confluent_kafka import TopicPartition
            
            for partition_id in topic_metadata.partitions:
                tp = TopicPartition(topic, partition_id)
                
                # Get low and high watermarks (faster with lower timeout)
                try:
                    low, high = self.consumer.get_watermark_offsets(tp, timeout=3)
                    
                    # If low < high, partition has messages
                    if low < high:
                        return False  # At least one partition has messages
                except Exception:
                    # If we can't get offsets, assume not empty to be safe
                    return False
            
            return True  # All partitions are empty
        except Exception as e:
            logger.debug(f"Error checking if topic {topic} is empty: {e}")
            return False  # Assume not empty on error
    
    def subscribe(self, topics: List[str]):
        """
        Subscribe to topics.
        
        Args:
            topics: List of topic names
        """
        if not self.consumer:
            self.connect()
        
        try:
            # Simple subscribe - auto.offset.reset='earliest' is already set in config
            self.consumer.subscribe(topics)
            logger.debug(f"Subscribed to topics: {topics}")
        except Exception as e:
            raise KafkaConnectionError(f"Failed to subscribe to topics: {e}")
    
    def poll(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """
        Poll for a single message.
        
        Args:
            timeout: Polling timeout in seconds
        
        Returns:
            Message dict with 'topic', 'partition', 'offset', 'value', 'key' or None
        """
        if not self.consumer:
            raise KafkaConnectionError("Consumer not connected")
        
        try:
            msg = self.consumer.poll(timeout=timeout)
            
            if msg is None:
                return None
            
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    return None
                else:
                    raise KafkaConnectionError(f"Consumer error: {msg.error()}")
            
            return {
                'topic': msg.topic(),
                'partition': msg.partition(),
                'offset': msg.offset(),
                'value': msg.value(),
                'key': msg.key(),
                'timestamp': msg.timestamp(),
                'headers': dict(msg.headers()) if msg.headers() else {}
            }
        except Exception as e:
            raise KafkaConnectionError(f"Failed to poll message: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

