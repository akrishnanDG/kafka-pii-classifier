"""Streaming consumer for real-time PII detection."""

import logging
import json
import time
from typing import Dict, Any, List, Optional, Callable
from threading import Event, Lock
from datetime import datetime
from pathlib import Path

from confluent_kafka import Consumer, KafkaError, TopicPartition
from confluent_kafka.admin import AdminClient

from ..utils.exceptions import KafkaConnectionError
from ..utils.logger import setup_logger

logger = logging.getLogger(__name__)


class StreamingConsumer:
    """
    Streaming consumer for real-time PII detection.
    
    Continuously polls Kafka topics and processes messages as they arrive.
    Tracks offsets to avoid reprocessing and supports graceful shutdown.
    """
    
    def __init__(
        self,
        kafka_config: Dict[str, Any],
        topics: List[str],
        message_handler: Callable[[Dict[str, Any]], None],
        offset_reset: str = 'latest',
        offset_storage_path: Optional[Path] = None,
        commit_interval: int = 100,  # Commit every N messages
        poll_timeout: float = 1.0
    ):
        """
        Initialize streaming consumer.
        
        Args:
            kafka_config: Kafka configuration dictionary
            topics: List of topics to subscribe to
            message_handler: Callback function to process each message
            offset_reset: 'latest' (new messages only) or 'earliest' (all messages)
            offset_storage_path: Path to store offsets (optional, uses Kafka consumer group)
            commit_interval: Commit offsets every N messages
            poll_timeout: Polling timeout in seconds
        """
        self.kafka_config = kafka_config
        self.topics = topics
        self.message_handler = message_handler
        self.offset_reset = offset_reset
        self.offset_storage_path = offset_storage_path
        self.commit_interval = commit_interval
        self.poll_timeout = poll_timeout
        
        self.consumer: Optional[Consumer] = None
        self.admin_client: Optional[AdminClient] = None
        self.running = False
        self.stop_event = Event()
        self.processed_count = 0
        self.error_count = 0
        self.last_commit_count = 0
        self.stats_lock = Lock()
        
        # Offset tracking (for file-based storage if needed)
        self.offset_storage: Dict[str, Dict[int, int]] = {}  # topic -> partition -> offset
        
    def _create_consumer_config(self) -> Dict[str, Any]:
        """Create consumer configuration."""
        consumer_config = {
            'bootstrap.servers': self.kafka_config['bootstrap_servers'],
            'group.id': self.kafka_config.get('group_id', 'pii-classification-streaming'),
            'auto.offset.reset': self.offset_reset,
            'enable.auto.commit': False,  # Manual commit for control
            'session.timeout.ms': 30000,
            'max.poll.interval.ms': 300000,  # 5 minutes
            'log_level': 0,
        }
        
        # Add security settings if provided
        if self.kafka_config.get('security_protocol'):
            consumer_config['security.protocol'] = self.kafka_config['security_protocol']
            if self.kafka_config.get('sasl_mechanism'):
                consumer_config['sasl.mechanism'] = self.kafka_config['sasl_mechanism']
            if self.kafka_config.get('sasl_username'):
                consumer_config['sasl.username'] = self.kafka_config['sasl_username']
            if self.kafka_config.get('sasl_password'):
                consumer_config['sasl.password'] = self.kafka_config['sasl_password']
        
        # Performance optimizations
        if self.kafka_config.get('fetch_min_bytes'):
            consumer_config['fetch.min.bytes'] = str(self.kafka_config['fetch_min_bytes'])
        if self.kafka_config.get('fetch_max_wait_ms'):
            consumer_config['fetch.wait.max.ms'] = str(self.kafka_config['fetch_max_wait_ms'])
        
        return consumer_config
    
    def connect(self):
        """Connect to Kafka."""
        try:
            config = self._create_consumer_config()
            self.consumer = Consumer(config)
            
            # Create admin client for metadata
            admin_config = {
                'bootstrap.servers': self.kafka_config['bootstrap_servers'],
            }
            if self.kafka_config.get('security_protocol'):
                admin_config['security.protocol'] = self.kafka_config['security_protocol']
                if self.kafka_config.get('sasl_mechanism'):
                    admin_config['sasl.mechanism'] = self.kafka_config['sasl_mechanism']
                if self.kafka_config.get('sasl_username'):
                    admin_config['sasl.username'] = self.kafka_config['sasl_username']
                if self.kafka_config.get('sasl_password'):
                    admin_config['sasl.password'] = self.kafka_config['sasl_password']
            
            self.admin_client = AdminClient(admin_config)
            
            logger.info(f"Streaming consumer connected (offset_reset: {self.offset_reset})")
        except Exception as e:
            raise KafkaConnectionError(f"Failed to connect streaming consumer: {e}")
    
    def _load_offsets(self) -> Dict[str, Dict[int, int]]:
        """Load offsets from file if configured."""
        if not self.offset_storage_path or not self.offset_storage_path.exists():
            return {}
        
        try:
            with open(self.offset_storage_path, 'r') as f:
                data = json.load(f)
                return {topic: {int(p): int(o) for p, o in partitions.items()}
                        for topic, partitions in data.items()}
        except Exception as e:
            logger.warning(f"Failed to load offsets from {self.offset_storage_path}: {e}")
            return {}
    
    def _save_offsets(self):
        """Save offsets to file if configured."""
        if not self.offset_storage_path:
            return
        
        try:
            self.offset_storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.offset_storage_path, 'w') as f:
                json.dump(self.offset_storage, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save offsets to {self.offset_storage_path}: {e}")
    
    def _seek_to_offsets(self):
        """Seek to saved offsets if available."""
        if not self.offset_storage_path:
            return
        
        offsets = self._load_offsets()
        if not offsets:
            return
        
        # Get current partition assignments
        partitions = []
        for topic in self.topics:
            metadata = self.consumer.list_topics(topic, timeout=10)
            if topic in metadata.topics:
                for partition_id in metadata.topics[topic].partitions:
                    if topic in offsets and partition_id in offsets[topic]:
                        tp = TopicPartition(topic, partition_id, offsets[topic][partition_id])
                        partitions.append(tp)
        
        if partitions:
            self.consumer.assign(partitions)
            logger.info(f"Seeked to saved offsets for {len(partitions)} partitions")
        else:
            # Subscribe normally if no saved offsets
            self.consumer.subscribe(self.topics)
    
    def subscribe(self):
        """Subscribe to topics."""
        if not self.consumer:
            self.connect()
        
        # Try to seek to saved offsets first
        if self.offset_storage_path:
            try:
                self._seek_to_offsets()
                return
            except Exception as e:
                logger.warning(f"Failed to seek to offsets, subscribing normally: {e}")
        
        # Normal subscription
        try:
            self.consumer.subscribe(self.topics)
            logger.info(f"Subscribed to topics: {self.topics}")
        except Exception as e:
            raise KafkaConnectionError(f"Failed to subscribe to topics: {e}")
    
    def _update_offsets(self, topic: str, partition: int, offset: int):
        """Update offset tracking."""
        if topic not in self.offset_storage:
            self.offset_storage[topic] = {}
        self.offset_storage[topic][partition] = offset
    
    def _commit_offsets(self, force: bool = False):
        """Commit offsets to Kafka and save to file."""
        if not self.consumer:
            return
        
        # Check if we should commit
        with self.stats_lock:
            should_commit = force or (self.processed_count - self.last_commit_count >= self.commit_interval)
            if not should_commit:
                return
        
        try:
            # Commit to Kafka (consumer group)
            self.consumer.commit(asynchronous=False)
            
            # Save to file if configured
            if self.offset_storage_path:
                self._save_offsets()
            
            with self.stats_lock:
                self.last_commit_count = self.processed_count
            
            logger.debug(f"Committed offsets (processed: {self.processed_count})")
        except Exception as e:
            logger.warning(f"Failed to commit offsets: {e}")
    
    def _process_message(self, msg) -> bool:
        """
        Process a single message.
        
        Returns:
            True if message was processed successfully, False otherwise
        """
        try:
            # Extract message data
            message_dict = {
                'topic': msg.topic(),
                'partition': msg.partition(),
                'offset': msg.offset(),
                'value': msg.value(),
                'key': msg.key(),
                'timestamp': msg.timestamp(),
                'headers': dict(msg.headers()) if msg.headers() else {}
            }
            
            # Update offset tracking
            self._update_offsets(
                message_dict['topic'],
                message_dict['partition'],
                message_dict['offset']
            )
            
            # Call message handler
            self.message_handler(message_dict)
            
            # Update stats
            with self.stats_lock:
                self.processed_count += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            with self.stats_lock:
                self.error_count += 1
            return False
    
    def start(self):
        """Start streaming consumer."""
        if self.running:
            logger.warning("Streaming consumer is already running")
            return
        
        self.running = True
        self.stop_event.clear()
        self.subscribe()
        
        logger.info("Streaming consumer started")
        logger.info(f"Topics: {self.topics}")
        logger.info(f"Offset reset: {self.offset_reset}")
        logger.info(f"Commit interval: {self.commit_interval} messages")
        
        try:
            while self.running and not self.stop_event.is_set():
                # Poll for messages
                msg = self.consumer.poll(timeout=self.poll_timeout)
                
                if msg is None:
                    continue
                
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        # End of partition - continue polling
                        continue
                    else:
                        logger.error(f"Consumer error: {msg.error()}")
                        with self.stats_lock:
                            self.error_count += 1
                        continue
                
                # Process message
                self._process_message(msg)
                
                # Commit offsets periodically
                self._commit_offsets()
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"Streaming consumer error: {e}", exc_info=True)
        finally:
            # Final commit
            self._commit_offsets(force=True)
            self.running = False
            logger.info("Streaming consumer stopped")
    
    def stop(self):
        """Stop streaming consumer gracefully."""
        logger.info("Stopping streaming consumer...")
        self.running = False
        self.stop_event.set()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics."""
        with self.stats_lock:
            return {
                'processed_count': self.processed_count,
                'error_count': self.error_count,
                'running': self.running,
                'topics': self.topics,
                'offset_reset': self.offset_reset
            }
    
    def disconnect(self):
        """Disconnect from Kafka."""
        if self.consumer:
            try:
                self.consumer.close()
                logger.info("Streaming consumer disconnected")
            except Exception as e:
                logger.warning(f"Error disconnecting consumer: {e}")
        
        if self.admin_client:
            self.admin_client = None

