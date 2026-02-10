"""Main PII classification agent orchestrator."""

import copy
import logging
import sys
from typing import Dict, Any, List, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

from .kafka.consumer import KafkaConsumerService
from .kafka.streaming_consumer import StreamingConsumer
from .kafka.sampler import (
    PercentageSampler,
    CountSampler,
    TimeBasedSampler,
    AllRecordsSampler
)
from .schema_registry.client import SchemaRegistryClientWrapper
from .schema_registry.tagger import SchemaTagger
from .pii.detector import PIIDetector
from .pii.classifier import FieldClassifier
from .schema_inference.inferrer import SchemaInferrer
from .reporting.generator import ReportGenerator
from .utils.helpers import safe_json_parse, flatten_dict

logger = logging.getLogger(__name__)


def _debug_print(message: str):
    """Print debug message only if DEBUG logging is enabled."""
    if logger.isEnabledFor(logging.DEBUG):
        print(message, flush=True)


class PIIClassificationAgent:
    """Main agent orchestrating the PII classification workflow."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the agent.

        Args:
            config: Full configuration dictionary
        """
        self.config = config

        # Initialize components
        self.kafka_consumer = KafkaConsumerService(config['kafka'])
        self.schema_registry = SchemaRegistryClientWrapper(config['schema_registry'])
        self.pii_detector = PIIDetector(config['pii_detection'])
        self.field_classifier = FieldClassifier(config['pii_detection'])
        self.schema_tagger = SchemaTagger(
            self.schema_registry,
            config['tagging']
        )

        # Schema inference (for schemaless topics)
        schemaless_config = config.get('schemaless_data', {})
        if schemaless_config.get('enabled', True):
            self.schema_inferrer = SchemaInferrer(
                schemaless_config.get('schema_inference', {})
            )
        else:
            self.schema_inferrer = None

        # Report generator
        self.report_generator = ReportGenerator(config.get('reporting', {}))

        # Parallel processing configuration
        self.parallel_workers = config.get('parallel_workers', 10)

    def run(self, topics: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run the PII classification workflow.

        Args:
            topics: Optional list of topics to analyze (uses config if None)

        Returns:
            Results dictionary
        """
        logger.info("Starting PII Classification Agent")

        # Connect to services (only for discovery, not for processing)
        self.kafka_consumer.connect()
        try:
            self.schema_registry.connect()
        except Exception:
            self.kafka_consumer.disconnect()
            raise

        try:
            # Get topics to analyze
            if topics is None:
                topics = self.config.get('topics', [])
                if not topics:
                    # List all topics
                    all_topics = self.kafka_consumer.list_topics()
                    topics = all_topics
                    logger.info(f"No topics specified, analyzing all {len(topics)} topics")

            # Results
            results = {
                'topics_analyzed': [],
                'total_fields_classified': 0,
                'total_pii_fields': 0,
                'errors': []
            }

            # Early return if no topics to process
            if not topics:
                logger.info("No topics to analyze")
                return results

            # Thread-safe locks for results
            results_lock = Lock()

            # Combined approach: Check if empty and process immediately if not empty
            # Divide topics among parallel workers - each worker checks and processes
            max_workers = min(self.parallel_workers, len(topics))
            print(f"Using {max_workers} parallel workers", flush=True)

            # Progress bar for all topics
            if TQDM_AVAILABLE:
                pbar = tqdm(
                    total=len(topics),
                    desc="Processing topics",
                    unit="topic",
                    file=sys.stdout,
                    ncols=120,
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}'
                )
            else:
                pbar = None

            empty_count = [0]  # Use list to make it mutable in closure

            def process_topic_wrapper(topic):
                """Wrapper: Check if empty, process if not empty, skip if empty."""
                try:
                    if pbar:
                        pbar.set_description(f"Processing: {topic[:50]}")

                    # Quick empty check first
                    check_consumer = None
                    try:
                        # Create a consumer for this check (thread-safe)
                        import uuid
                        kafka_config = copy.deepcopy(self.config['kafka'])
                        kafka_config['group_id'] = f"pii-check-{uuid.uuid4().hex[:8]}"
                        check_consumer = KafkaConsumerService(kafka_config)
                        check_consumer.connect()

                        is_empty = check_consumer.is_topic_empty(topic)

                        if is_empty:
                            # Topic is empty - add to results and skip processing
                            if pbar:
                                with results_lock:
                                    empty_count[0] += 1
                                    pbar.update(1)

                            return {
                                'topic': topic,
                                'samples': 0,
                                'fields_classified': 0,
                                'pii_fields_found': 0,
                                'schemaless': False,
                                'empty': True
                            }
                    except Exception as e:
                        logger.debug(f"Error checking if topic {topic} is empty: {e}")
                        # If check fails, assume not empty and continue processing
                    finally:
                        if check_consumer is not None:
                            try:
                                check_consumer.disconnect()
                            except Exception:
                                pass

                    # Topic is not empty - process it immediately
                    result = self._process_topic(topic)
                    if pbar:
                        with results_lock:
                            pbar.update(1)
                    return result
                except Exception as e:
                    error_msg = f"Error processing topic {topic}: {e}"
                    logger.error(error_msg, exc_info=True)
                    if pbar:
                        pbar.update(1)
                    return {'error': error_msg, 'topic': topic}

            # Process all topics in parallel (each worker checks empty and processes if not)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_topic = {
                    executor.submit(process_topic_wrapper, topic): topic
                    for topic in topics
                }

                for future in as_completed(future_to_topic):
                    topic = future_to_topic[future]
                    try:
                        topic_results = future.result()

                        if 'error' in topic_results:
                            with results_lock:
                                results['errors'].append(topic_results['error'])
                        else:
                            with results_lock:
                                results['topics_analyzed'].append(topic_results)
                                if not topic_results.get('empty', False):
                                    results['total_fields_classified'] += topic_results.get('fields_classified', 0)
                                    results['total_pii_fields'] += topic_results.get('pii_fields_found', 0)
                                if pbar:
                                    pbar.set_postfix({
                                        'empty': empty_count[0],
                                        'PII': results['total_pii_fields'],
                                        'Fields': results['total_fields_classified'],
                                        'Errors': len(results['errors'])
                                    })
                    except Exception as e:
                        error_msg = f"Error processing topic {topic}: {e}"
                        with results_lock:
                            results['errors'].append(error_msg)
                        if pbar:
                            with results_lock:
                                pbar.set_postfix({'Errors': len(results['errors'])})

            if pbar:
                pbar.close()

            # Count empty topics for summary
            empty_topics = [r['topic'] for r in results['topics_analyzed'] if r.get('empty', False)]
            if empty_topics:
                print(f"Skipped {len(empty_topics)} empty topic(s)", flush=True)

            # Generate reports
            report_files = self.report_generator.generate(results)
            if report_files:
                results['report_files'] = [str(f) for f in report_files]
                logger.info(f"Generated {len(report_files)} report(s)")

            logger.info(f"Analysis complete. Analyzed {len(results['topics_analyzed'])} topics")
            return results
        finally:
            self.kafka_consumer.disconnect()

    def _process_topic(self, topic: str) -> Dict[str, Any]:
        """
        Process a single topic.

        Args:
            topic: Topic name

        Returns:
            Topic results
        """
        logger.debug(f"Processing topic: {topic}")

        # Create a new consumer for this topic (thread-safe)
        # Use unique group ID to avoid offset conflicts
        import uuid
        kafka_config = copy.deepcopy(self.config['kafka'])
        kafka_config['group_id'] = f"pii-classification-agent-{topic}-{uuid.uuid4().hex[:8]}"
        topic_consumer = KafkaConsumerService(kafka_config)
        topic_consumer.connect()

        try:
            # Fast empty check (already checked, but double-check for safety)
            if topic_consumer.is_topic_empty(topic):
                logger.debug(f"Topic {topic} is empty, skipping")
                return {
                    'topic': topic,
                    'samples': 0,
                    'fields_classified': 0,
                    'pii_fields_found': 0,
                    'schemaless': False,
                    'empty': True
                }

            logger.debug(f"Topic {topic}: Checking schema...")
            # Check if schema exists
            subject = f"{topic}-value"
            schema_info = self.schema_registry.get_schema(subject)
            is_schemaless = schema_info is None

            logger.debug(f"Topic {topic}: {'schemaless' if is_schemaless else 'has schema'}")

            # Sample messages
            sampling_config = self.config.get('sampling', {})
            strategy = sampling_config.get('strategy', 'percentage')

            # Check if full analysis is requested
            analyze_all = sampling_config.get('analyze_all_records', False)
            max_for_full = sampling_config.get('max_records_full_analysis', 10000)

            # Determine partition count for auto-switching
            partition_count = topic_consumer.get_partition_count(topic)

            if analyze_all:
                sampler = AllRecordsSampler()
            elif strategy == 'all':
                sampler = AllRecordsSampler()
            elif strategy == 'percentage':
                # Handle percentage - can be 0.02 (decimal) or 2 (percentage)
                sample_pct = sampling_config.get('sample_percentage', 5)
                if sample_pct > 1.0:
                    sample_pct = sample_pct / 100.0  # Convert 2 to 0.02
                # Otherwise use as-is (already 0.02)
                sampler = PercentageSampler(
                    percentage=sample_pct,
                    max_per_partition=sampling_config.get('max_samples_per_partition', 100),
                    min_per_partition=sampling_config.get('min_samples_per_partition', 10)
                )
            elif strategy == 'count':
                sampler = CountSampler(
                    count=sampling_config.get('sample_count', 100)
                )
            elif strategy == 'time_based':
                # Parse time window (e.g., "1h", "2h", "30m")
                time_window_str = str(sampling_config.get('sample_time_window', '1h'))
                time_window_hours = self._parse_time_window(time_window_str)
                sampler = TimeBasedSampler(time_window_hours=time_window_hours)
            else:
                # Default to percentage (same as 'percentage' strategy)
                sample_pct = sampling_config.get('sample_percentage', 5)
                if sample_pct > 1.0:
                    sample_pct = sample_pct / 100.0
                sampler = PercentageSampler(
                    percentage=sample_pct,
                    max_per_partition=sampling_config.get('max_samples_per_partition', 100),
                    min_per_partition=sampling_config.get('min_samples_per_partition', 10)
                )

            logger.debug(f"Topic {topic}: Sampling messages...")
            samples = self._sample_topic(topic, sampler, topic_consumer, show_progress=False)
            logger.debug(f"Topic {topic}: Collected {len(samples)} samples")

            if not samples:
                return {
                    'topic': topic,
                    'samples': 0,
                    'fields_classified': 0,
                    'pii_fields_found': 0,
                    'schemaless': is_schemaless
                }

            # Analyze samples
            logger.debug(f"Topic {topic}: Analyzing {len(samples)} samples for PII...")
            field_detections = self._analyze_samples(samples, topic, is_schemaless)

            # Classify fields
            logger.debug(f"Topic {topic}: Classifying fields...")
            classifications = self.field_classifier.classify_fields(
                field_detections,
                len(samples)
            )
            logger.debug(f"Topic {topic}: Found {len(classifications)} classified fields")

            # Tag schema (if enabled)
            tagging_results = {}
            if self.config.get('tagging', {}).get('enabled', False):
                tagging_results = self.schema_tagger.tag_schema(
                    subject,
                    classifications,
                    schema_info
                )

            return {
                'topic': topic,
                'samples': len(samples),
                'fields_classified': len(classifications),
                'pii_fields_found': sum(1 for cls in classifications.values() if cls.pii_types),
            'classifications': {
                field_path: {
                    'tags': cls.tags,
                    'pii_types': [pt.value for pt in cls.pii_types],
                    'confidence': cls.confidence,
                    'detection_rate': cls.detection_rate,
                    'sample_values': cls.sample_values if hasattr(cls, 'sample_values') else []
                }
                for field_path, cls in classifications.items()
            },
            'tagging': tagging_results,
            'schemaless': is_schemaless
        }
        finally:
            topic_consumer.disconnect()

    def _sample_partition(self, topic: str, partition_id: int, sampler, kafka_config: dict) -> List[Dict[str, Any]]:
        """Sample messages from a single partition - runs in its own thread. Uses only confluent_kafka.

        Strategy: Read last N messages into memory, then sample from that list.
        This is much simpler and faster than sampling during polling.
        """
        from confluent_kafka import Consumer, KafkaError, TopicPartition
        import uuid

        # Create consumer
        consumer_config = {
            'bootstrap.servers': kafka_config['bootstrap_servers'],
            'group.id': f'sample-{uuid.uuid4().hex[:8]}',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
        }
        # Only add security settings if configured
        security_protocol = kafka_config.get('security_protocol', 'PLAINTEXT')
        consumer_config['security.protocol'] = security_protocol
        if security_protocol != 'PLAINTEXT':
            if kafka_config.get('sasl_mechanism'):
                consumer_config['sasl.mechanism'] = kafka_config['sasl_mechanism']
            if kafka_config.get('sasl_username'):
                consumer_config['sasl.username'] = kafka_config['sasl_username']
            if kafka_config.get('sasl_password'):
                consumer_config['sasl.password'] = kafka_config['sasl_password']
        consumer = Consumer(consumer_config)

        try:
            # Check if partition is empty (beginning == end offset)
            tp = TopicPartition(topic, partition_id)
            _debug_print(f"[DEBUG] Partition {partition_id}: Getting offsets...")
            low, high = consumer.get_watermark_offsets(tp, timeout=5)
            _debug_print(f"[DEBUG] Partition {partition_id}: low={low}, high={high}")

            if low == high:  # Empty partition - skip immediately
                _debug_print(f"[DEBUG] Partition {partition_id}: Empty, skipping")
                return []

            # Strategy: Read last N messages into memory, then sample from that list
            # This is much simpler and avoids all the complex termination logic
            max_per_partition = getattr(sampler, 'max_per_partition', 100)
            min_per_partition = getattr(sampler, 'min_per_partition', 10)

            # For percentage sampling, calculate how many messages we need
            if isinstance(sampler, PercentageSampler):
                percentage = sampler.percentage
                # We need at least max_per_partition / percentage messages to get max samples
                # Add buffer: read 2x what we need to ensure good coverage
                messages_to_read = int(max_per_partition / percentage) * 2
                messages_to_read = max(messages_to_read, min_per_partition * 10)  # At least 100 for min samples
            else:
                messages_to_read = max_per_partition * 10  # Default: 10x max samples

            # Cap at 200 messages max for speed (don't read too much)
            # For 10% sampling: 200 messages = 20 samples (plenty)
            messages_to_read = min(messages_to_read, 200)
            total_messages = high - low
            messages_to_read = min(messages_to_read, total_messages)

            _debug_print(f"[DEBUG] Partition {partition_id}: Will read {messages_to_read} messages (for max {max_per_partition} samples)")

            if messages_to_read == 0:
                _debug_print(f"[DEBUG] Partition {partition_id}: Empty partition")
                return []

            # Start from latest messages
            start_offset = max(low, high - messages_to_read)
            _debug_print(f"[DEBUG] Partition {partition_id}: Reading last {messages_to_read} messages (from offset {start_offset} to {high-1})")

            # Assign to partition and start from calculated offset
            tp.offset = start_offset
            consumer.assign([tp])

            # Warmup - poll a few times to ensure consumer is ready
            for _ in range(3):
                consumer.poll(timeout=0.1)

            # Initialize variables
            all_messages = []
            samples = []

            # Read ALL messages into memory - SIMPLE: read until we reach the end or hit limit
            _debug_print(f"[DEBUG] Partition {partition_id}: Reading up to {messages_to_read} messages into memory...")
            messages_read = 0
            poll_count = 0
            consecutive_none = 0

            while messages_read < messages_to_read:
                poll_count += 1
                if poll_count % 100 == 0:  # Less frequent logging
                    _debug_print(f"[DEBUG] Partition {partition_id}: Polling (attempt {poll_count}, read {messages_read}/{messages_to_read})...")

                msg = consumer.poll(timeout=0.2)  # Faster timeout - 200ms for speed

                if msg is None:
                    consecutive_none += 1
                    # If we've read messages and get None, we're at the end
                    if messages_read > 0:
                        _debug_print(f"[DEBUG] Partition {partition_id}: Poll returned None after {messages_read} messages (at end) - BREAKING")
                        break
                    # If we haven't read anything yet, give it a few tries
                    if consecutive_none >= 3:
                        _debug_print(f"[DEBUG] Partition {partition_id}: Poll returned None {consecutive_none} times, no messages - BREAKING")
                        break
                    # Continue for warmup
                    continue

                consecutive_none = 0

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        _debug_print(f"[DEBUG] Partition {partition_id}: Reached EOF after {messages_read} messages")
                        break
                    _debug_print(f"[DEBUG] Partition {partition_id}: Error - {msg.error()}")
                    break

                messages_read += 1
                current_offset = msg.offset()

                # Create message dict
                msg_dict = {
                    'topic': msg.topic(),
                    'partition': partition_id,
                    'offset': current_offset,
                    'value': msg.value(),
                    'key': msg.key(),
                }

                all_messages.append(msg_dict)

                # Stop immediately if we've reached the end
                if current_offset >= high - 1:
                    _debug_print(f"[DEBUG] Partition {partition_id}: Reached end (offset={current_offset}, high={high}), read {messages_read} messages")
                    break

                if messages_read % 100 == 0:
                    _debug_print(f"[DEBUG] Partition {partition_id}: Read {messages_read} messages...")

            _debug_print(f"[DEBUG] Partition {partition_id}: Read {len(all_messages)} messages into memory, now sampling...")

            # Skip-based sampling optimization: If enabled, read every Nth message directly
            # This avoids reading all messages and is much faster while maintaining accuracy
            sampling_config = self.config.get('sampling', {})
            use_skip_based = sampling_config.get('use_skip_based_sampling', False)

            if use_skip_based and isinstance(sampler, PercentageSampler):
                # Calculate skip interval (for 5% = every 20th message)
                percentage = sampler.percentage
                skip_interval = max(1, int(1 / percentage))  # For 5% = 20

                # Use skip-based sampling: read every Nth message directly
                _debug_print(f"[DEBUG] Partition {partition_id}: Using skip-based sampling (every {skip_interval}th message)")

                # Re-read with skip-based approach
                samples = []
                tp.offset = start_offset
                consumer.assign([tp])

                # Warmup
                for _ in range(3):
                    consumer.poll(timeout=0.1)

                messages_read = 0
                skip_counter = 0
                early_termination = sampling_config.get('early_termination', False)

                while len(samples) < max_per_partition:
                    msg = consumer.poll(timeout=0.2)

                    if msg is None:
                        if messages_read > 0:
                            break
                        continue

                    if msg.error():
                        if msg.error().code() == KafkaError._PARTITION_EOF:
                            break
                        break

                    messages_read += 1
                    skip_counter += 1

                    # Sample every Nth message
                    if skip_counter >= skip_interval:
                        msg_dict = {
                            'topic': msg.topic(),
                            'partition': partition_id,
                            'offset': msg.offset(),
                            'value': msg.value(),
                            'key': msg.key(),
                        }
                        samples.append(msg_dict)
                        skip_counter = 0

                        # Early termination if we have enough samples
                        if early_termination and len(samples) >= max_per_partition:
                            _debug_print(f"[DEBUG] Partition {partition_id}: Early termination at {len(samples)} samples")
                            break

                    # Safety check: don't read too many messages
                    if messages_read >= messages_to_read * skip_interval:
                        break

                _debug_print(f"[DEBUG] Partition {partition_id}: Skip-based sampling collected {len(samples)} samples from {messages_read} messages")
                return samples

            # Fallback to in-memory sampling (original approach)
            # Now sample from the in-memory list - FAST in-memory sampling
            if isinstance(sampler, PercentageSampler):
                percentage = sampler.percentage
                _debug_print(f"[DEBUG] Partition {partition_id}: Sampling {percentage*100}% from {len(all_messages)} messages")

                # Calculate how many to sample
                target_count = int(len(all_messages) * percentage)
                target_count = max(min_per_partition, min(target_count, max_per_partition))

                # Fast sampling: use list slicing with step
                if len(all_messages) > 0:
                    step = max(1, len(all_messages) // target_count)
                    # Use list slicing - much faster than loop
                    samples = all_messages[::step][:max_per_partition]

                _debug_print(f"[DEBUG] Partition {partition_id}: Sampled {len(samples)} messages from {len(all_messages)}")
            else:
                # For other samplers, use their logic
                context = {
                    'partition': partition_id,
                    'partition_samples': {partition_id: 0}
                }
                for msg_dict in all_messages:
                    if len(samples) >= max_per_partition:
                        break
                    if sampler.should_sample(msg_dict, context):
                        samples.append(msg_dict)
                        context['partition_samples'][partition_id] = len(samples)

        finally:
            try:
                consumer.close()
            except Exception as e:
                _debug_print(f"[DEBUG] Partition {partition_id}: Error closing consumer: {e}")

        _debug_print(f"[DEBUG] Partition {partition_id}: Done - collected {len(samples)} samples from {len(all_messages)} messages")
        return samples

    def _sample_topic(self, topic: str, sampler, consumer: KafkaConsumerService, show_progress: bool = False) -> List[Dict[str, Any]]:
        """Sample messages from a topic - parallel processing of partitions."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Get partition count
        partition_count = consumer.get_partition_count(topic)
        kafka_config = self.config['kafka']

        # Get max partitions limit from config
        sampling_config = self.config.get('sampling', {})
        max_partitions_per_topic = sampling_config.get('max_partitions_per_topic')

        # Limit partitions to scan if configured
        partitions_to_scan = partition_count
        if max_partitions_per_topic is not None and max_partitions_per_topic > 0:
            partitions_to_scan = min(partition_count, max_partitions_per_topic)
            logger.info(f"Topic {topic}: Limiting partition scan to {partitions_to_scan} of {partition_count} partitions")

        # Process each partition in parallel
        all_samples = []
        partitions_with_samples = 0  # Track partitions that have samples

        # Use more workers for parallel partition processing (configurable)
        max_parallel_partitions = self.config.get('max_parallel_partitions', 30)
        max_workers = min(partitions_to_scan, max_parallel_partitions)
        _debug_print(f"[DEBUG] Topic {topic}: Using {max_workers} workers for {partitions_to_scan} partitions")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit only the partitions we want to scan
            futures = {
                executor.submit(self._sample_partition, topic, p, sampler, kafka_config): p
                for p in range(partitions_to_scan)
            }

            _debug_print(f"[DEBUG] Topic {topic}: Waiting for {len(futures)} partition(s) to complete...")
            completed = 0
            remaining_futures = set(futures.keys())

            for future in as_completed(futures):
                partition_id = futures[future]
                completed += 1
                _debug_print(f"[DEBUG] Topic {topic}: Partition {partition_id} completed ({completed}/{len(futures)})")

                try:
                    _debug_print(f"[DEBUG] Topic {topic}: Getting result from partition {partition_id}...")
                    partition_samples = future.result(timeout=60)  # 60 second timeout per partition
                    _debug_print(f"[DEBUG] Topic {topic}: Partition {partition_id} returned {len(partition_samples)} samples")

                    # Only count partitions that have samples
                    if len(partition_samples) > 0:
                        partitions_with_samples += 1
                        all_samples.extend(partition_samples)

                        # Check if we've reached the limit after finding samples in this partition
                        if max_partitions_per_topic is not None and max_partitions_per_topic > 0:
                            if partitions_with_samples >= max_partitions_per_topic:
                                logger.info(f"Topic {topic}: Found samples in {partitions_with_samples} partitions (limit: {max_partitions_per_topic}), stopping early")
                                _debug_print(f"[DEBUG] Topic {topic}: Cancelling remaining {len(remaining_futures) - 1} partition(s)")
                                # Cancel remaining futures
                                for remaining_future in remaining_futures:
                                    if remaining_future != future:
                                        remaining_future.cancel()
                                # Break out of the loop
                                break
                    else:
                        _debug_print(f"[DEBUG] Topic {topic}: Partition {partition_id} had no samples (empty or filtered)")

                except Exception as e:
                    _debug_print(f"[DEBUG] Topic {topic}: ERROR getting result from partition {partition_id}: {e}")
                    logger.error(f"Error sampling partition {partition_id} of topic {topic}: {e}")

                # Remove completed future from remaining set
                remaining_futures.discard(future)

            _debug_print(f"[DEBUG] Topic {topic}: Completed scanning, found samples in {partitions_with_samples} partitions, total samples: {len(all_samples)}")

        logger.info(f"Topic {topic}: collected {len(all_samples)} total samples from {partitions_with_samples} partitions (scanned {completed} of {partitions_to_scan} partitions)")
        return all_samples

    def _analyze_samples(
        self,
        samples: List[Dict[str, Any]],
        topic: str,
        is_schemaless: bool
    ) -> Dict[str, List[List[Any]]]:
        """Analyze samples for PII - with schema-level LLM detection and parallel processing."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from .utils.avro_deserializer import deserialize_message

        field_detections = {}
        field_detections_lock = Lock()  # Thread-safe access to field_detections

        # Pre-get schema info to avoid repeated lookups (speed optimization)
        schema_type = None
        if not is_schemaless:
            subject = f"{topic}-value"
            schema_info = self.schema_registry.get_schema(subject)
            if schema_info:
                schema_type = schema_info.get('schema_type', 'AVRO')

        # First, parse all samples to get field names and data for schema-level detection
        parsed_samples = []
        all_field_names = set()

        for msg in samples:
            value = msg.get('value')
            parsed = None

            try:
                parsed = deserialize_message(
                    value,
                    self.schema_registry.client,
                    schema_type=schema_type,
                    subject=f"{topic}-value" if not is_schemaless else None
                )
            except Exception as e:
                logger.debug(f"Failed to deserialize message: {e}, trying JSON fallback")
                parsed = safe_json_parse(value)

            if parsed:
                if is_schemaless and self.schema_inferrer:
                    fields = self.schema_inferrer.json_parser.extract_fields(parsed)
                else:
                    fields = flatten_dict(parsed)

                parsed_samples.append(fields)
                all_field_names.update(fields.keys())

        # SCHEMA-LEVEL DETECTION: If LLM agent is configured, use it efficiently (1 call per topic)
        if self.pii_detector.has_schema_detectors() and parsed_samples:
            logger.info(f"Topic {topic}: Running schema-level LLM analysis on {len(all_field_names)} fields...")

            # Call LLM agent once with all fields and samples
            schema_detections = self.pii_detector.detect_in_schema(
                list(all_field_names),
                parsed_samples[:10]  # Use up to 10 samples for context
            )

            # Add schema-level detections to field_detections
            # These are high-confidence detections that apply to all samples
            for field_path, detections in schema_detections.items():
                if field_path not in field_detections:
                    field_detections[field_path] = []
                # Add detection for each sample that has this field
                for sample in parsed_samples:
                    if field_path in sample:
                        field_detections[field_path].append(detections)

            logger.info(f"Topic {topic}: Schema-level analysis found {len(schema_detections)} PII fields")

        # PER-FIELD DETECTION: Run pattern detector and other per-field detectors
        def analyze_single_sample(sample_fields: Dict[str, Any]) -> Dict[str, List[Any]]:
            """Analyze a single sample with per-field detectors."""
            sample_detections = {}

            for field_path, field_value in sample_fields.items():
                detections = self.pii_detector.detect_in_field(field_path, field_value)
                if detections:
                    sample_detections[field_path] = detections

            return sample_detections

        # Process samples in parallel for per-field detection
        max_workers = min(len(parsed_samples), 20)
        if len(parsed_samples) > 10:
            _debug_print(f"[DEBUG] Topic {topic}: Running per-field analysis on {len(parsed_samples)} samples")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(analyze_single_sample, sample): i
                for i, sample in enumerate(parsed_samples)
            }

            completed = 0
            for future in as_completed(futures):
                sample_idx = futures[future]
                completed += 1
                if completed % 25 == 0 and len(parsed_samples) > 25:
                    _debug_print(f"[DEBUG] Topic {topic}: Analyzed {completed}/{len(parsed_samples)} samples")
                try:
                    sample_detections = future.result()
                    # Merge into main field_detections (thread-safe)
                    with field_detections_lock:
                        for field_path, detections in sample_detections.items():
                            if field_path not in field_detections:
                                field_detections[field_path] = []
                            field_detections[field_path].append(detections)
                except Exception as e:
                    logger.error(f"Error analyzing sample {sample_idx}: {e}")

        if len(parsed_samples) > 10:
            _debug_print(f"[DEBUG] Topic {topic}: Completed PII analysis for {len(parsed_samples)} samples")
        return field_detections

    def _parse_time_window(self, time_window_str: str) -> float:
        """
        Parse time window string (e.g., "1h", "30m", "2h") to hours.

        Args:
            time_window_str: Time window string

        Returns:
            Time window in hours
        """
        time_window_str = time_window_str.strip().lower()

        if time_window_str.endswith('h'):
            return float(time_window_str[:-1])
        elif time_window_str.endswith('m'):
            return float(time_window_str[:-1]) / 60.0
        elif time_window_str.endswith('d'):
            return float(time_window_str[:-1]) * 24.0
        else:
            # Assume hours if no unit
            try:
                return float(time_window_str)
            except ValueError:
                return 1.0  # Default to 1 hour

    def run_streaming(
        self,
        topics: Optional[List[str]] = None,
        offset_reset: str = 'latest',
        offset_storage_path: Optional[Path] = None,
        commit_interval: int = 100,
        enable_tagging: bool = False
    ) -> StreamingConsumer:
        """
        Run in streaming mode for real-time PII detection.

        Args:
            topics: List of topics to stream (uses config if None)
            offset_reset: 'latest' (new messages) or 'earliest' (all messages)
            offset_storage_path: Path to store offsets for resume
            commit_interval: Commit offsets every N messages
            enable_tagging: Whether to tag schemas when PII is detected

        Returns:
            StreamingConsumer instance (call .start() to begin streaming)
        """
        # Get topics
        if topics is None:
            topics = self.config.get('topics', [])
            if isinstance(topics, dict):
                topics = []  # Empty means all topics

        if not topics:
            # Get all topics from Kafka
            self.kafka_consumer.connect()
            topics = self.kafka_consumer.list_topics()
            self.kafka_consumer.disconnect()
            logger.info(f"Streaming all {len(topics)} topics")

        # Connect to schema registry
        self.schema_registry.connect()

        # Message handler for streaming
        def handle_message(msg: Dict[str, Any]):
            """Process each message for PII detection."""
            topic = msg.get('topic', 'unknown')
            value = msg.get('value')

            if not value:
                return

            # Parse message
            parsed = safe_json_parse(value)
            if not parsed:
                return

            # Extract and flatten fields
            fields = flatten_dict(parsed)

            # Detect PII
            detections = {}
            for field_path, field_value in fields.items():
                field_detections = self.pii_detector.detect_in_field(field_path, field_value)
                if field_detections:
                    detections[field_path] = field_detections

            if detections:
                # Log detections
                pii_types = set()
                for field_dets in detections.values():
                    for det in field_dets:
                        pii_types.add(det.pii_type.value)

                logger.info(f"PII detected in {topic}: {', '.join(pii_types)}")

                # Tag schema if enabled
                if enable_tagging:
                    subject = f"{topic}-value"
                    schema_info = self.schema_registry.get_schema(subject)
                    if schema_info:
                        # Classify fields
                        field_detection_lists = {k: [v] for k, v in detections.items()}
                        classifications = self.field_classifier.classify_fields(
                            field_detection_lists, 1
                        )
                        if classifications:
                            self.schema_tagger.tag_schema(subject, classifications, schema_info)

        # Create streaming consumer
        streaming_consumer = StreamingConsumer(
            kafka_config=self.config['kafka'],
            topics=list(topics),
            message_handler=handle_message,
            offset_reset=offset_reset,
            offset_storage_path=offset_storage_path,
            commit_interval=commit_interval
        )

        return streaming_consumer
