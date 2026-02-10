"""Tests for StreamingConsumer and API rate limiting."""

import time
import pytest
from unittest.mock import patch, MagicMock, PropertyMock, call


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kafka_config(**overrides):
    cfg = {
        'bootstrap_servers': 'localhost:9092',
        'group_id': 'test-streaming-group',
    }
    cfg.update(overrides)
    return cfg


def _noop_handler(msg):
    """No-op message handler."""
    pass


def _build_consumer(handler=None, **kwargs):
    """Instantiate a StreamingConsumer with mocked Kafka classes."""
    from src.kafka.streaming_consumer import StreamingConsumer
    return StreamingConsumer(
        kafka_config=_kafka_config(),
        topics=['test-topic'],
        message_handler=handler or _noop_handler,
        **kwargs,
    )


# ===================================================================
# _update_offsets stores offset+1 correctly
# ===================================================================

class TestUpdateOffsets:
    """_update_offsets stores offset+1 correctly.

    Note: The _update_offsets method itself stores the value it receives.
    The +1 adjustment happens in _process_message which calls
    _update_offsets(topic, partition, offset + 1).
    """

    def test_stores_offset_value(self):
        """_update_offsets stores the exact value passed (the caller adds +1)."""
        consumer = _build_consumer()

        consumer._update_offsets('my-topic', 0, 42)

        assert consumer.offset_storage['my-topic'][0] == 42

    def test_process_message_calls_update_with_offset_plus_one(self):
        """_process_message should store offset+1 (the NEXT offset to read)."""
        consumer = _build_consumer()

        # Create a mock Kafka message
        mock_msg = MagicMock()
        mock_msg.topic.return_value = 'my-topic'
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 99
        mock_msg.value.return_value = b'{"key": "value"}'
        mock_msg.key.return_value = None
        mock_msg.timestamp.return_value = (0, 1234567890)
        mock_msg.headers.return_value = None

        consumer._process_message(mock_msg)

        # Should store offset + 1 = 100
        assert consumer.offset_storage['my-topic'][0] == 100

    def test_multiple_partitions_tracked_independently(self):
        consumer = _build_consumer()

        consumer._update_offsets('topic-a', 0, 10)
        consumer._update_offsets('topic-a', 1, 20)
        consumer._update_offsets('topic-b', 0, 30)

        assert consumer.offset_storage['topic-a'][0] == 10
        assert consumer.offset_storage['topic-a'][1] == 20
        assert consumer.offset_storage['topic-b'][0] == 30

    def test_offset_overwritten_on_later_update(self):
        consumer = _build_consumer()

        consumer._update_offsets('t', 0, 5)
        consumer._update_offsets('t', 0, 15)

        assert consumer.offset_storage['t'][0] == 15


# ===================================================================
# Circuit breaker triggers after threshold
# ===================================================================

class TestCircuitBreaker:
    """Circuit breaker triggers after threshold consecutive errors."""

    def test_circuit_breaker_triggers_at_threshold(self):
        """After _circuit_breaker_threshold consecutive handler failures,
        the consumer should call stop()."""
        consumer = _build_consumer()
        consumer._circuit_breaker_threshold = 3

        # Create a mock message
        mock_msg = MagicMock()
        mock_msg.topic.return_value = 'topic'
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 0
        mock_msg.value.return_value = b'data'
        mock_msg.key.return_value = None
        mock_msg.timestamp.return_value = (0, 0)
        mock_msg.headers.return_value = None

        # Handler that always fails
        consumer.message_handler = MagicMock(side_effect=RuntimeError('fail'))

        with patch.object(consumer, 'stop') as mock_stop:
            for _ in range(3):
                consumer._process_message(mock_msg)

            mock_stop.assert_called_once()

    def test_circuit_breaker_does_not_trigger_below_threshold(self):
        consumer = _build_consumer()
        consumer._circuit_breaker_threshold = 5

        mock_msg = MagicMock()
        mock_msg.topic.return_value = 'topic'
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 0
        mock_msg.value.return_value = b'data'
        mock_msg.key.return_value = None
        mock_msg.timestamp.return_value = (0, 0)
        mock_msg.headers.return_value = None

        consumer.message_handler = MagicMock(side_effect=RuntimeError('fail'))

        with patch.object(consumer, 'stop') as mock_stop:
            for _ in range(4):  # Below threshold of 5
                consumer._process_message(mock_msg)

            mock_stop.assert_not_called()

    def test_consecutive_errors_reset_on_success(self):
        """A successful message should reset _consecutive_errors to 0."""
        consumer = _build_consumer()
        consumer._circuit_breaker_threshold = 5

        mock_msg = MagicMock()
        mock_msg.topic.return_value = 'topic'
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 0
        mock_msg.value.return_value = b'data'
        mock_msg.key.return_value = None
        mock_msg.timestamp.return_value = (0, 0)
        mock_msg.headers.return_value = None

        # First: 3 failures
        consumer.message_handler = MagicMock(side_effect=RuntimeError('fail'))
        for _ in range(3):
            consumer._process_message(mock_msg)
        assert consumer._consecutive_errors == 3

        # Then: 1 success
        consumer.message_handler = MagicMock()  # no side_effect = success
        consumer._process_message(mock_msg)
        assert consumer._consecutive_errors == 0


# ===================================================================
# disconnect sets consumer to None
# ===================================================================

class TestDisconnect:
    """disconnect sets consumer to None."""

    @patch('src.kafka.streaming_consumer.Consumer')
    @patch('src.kafka.streaming_consumer.AdminClient')
    def test_disconnect_sets_consumer_none(self, mock_admin, mock_consumer_cls):
        consumer = _build_consumer()

        # Simulate a connected state
        mock_kafka_consumer = MagicMock()
        consumer.consumer = mock_kafka_consumer
        consumer.admin_client = MagicMock()

        consumer.disconnect()

        assert consumer.consumer is None
        assert consumer.admin_client is None
        mock_kafka_consumer.close.assert_called_once()

    @patch('src.kafka.streaming_consumer.Consumer')
    @patch('src.kafka.streaming_consumer.AdminClient')
    def test_disconnect_when_already_none(self, mock_admin, mock_consumer_cls):
        """Calling disconnect when consumer is already None should be a no-op."""
        consumer = _build_consumer()
        consumer.consumer = None
        consumer.admin_client = None

        # Should not raise
        consumer.disconnect()

        assert consumer.consumer is None

    @patch('src.kafka.streaming_consumer.Consumer')
    @patch('src.kafka.streaming_consumer.AdminClient')
    def test_disconnect_handles_close_error(self, mock_admin, mock_consumer_cls):
        """If consumer.close() raises, disconnect should handle it and still
        set consumer to None."""
        consumer = _build_consumer()

        mock_kafka_consumer = MagicMock()
        mock_kafka_consumer.close.side_effect = RuntimeError('close failed')
        consumer.consumer = mock_kafka_consumer

        consumer.disconnect()

        assert consumer.consumer is None


# ===================================================================
# _check_rate_limit from api.py
# ===================================================================

class TestCheckRateLimit:
    """Test _check_rate_limit allows and blocks."""

    def test_allows_requests_under_limit(self):
        """Requests under the max limit should be allowed."""
        from src.integration import api

        # Reset state
        api._rate_limit_buckets.clear()
        api._rate_limit_max = 5
        api._rate_limit_window = 60

        # Use Flask test request context
        with api.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.1'}
        ):
            for _ in range(5):
                assert api._check_rate_limit() is True

    def test_blocks_requests_over_limit(self):
        """Requests beyond the max limit should be blocked."""
        from src.integration import api

        api._rate_limit_buckets.clear()
        api._rate_limit_max = 3
        api._rate_limit_window = 60

        with api.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.2'}
        ):
            for _ in range(3):
                api._check_rate_limit()

            # 4th request should be blocked
            assert api._check_rate_limit() is False

    def test_different_clients_have_separate_limits(self):
        """Each client IP should have its own rate limit bucket."""
        from src.integration import api

        api._rate_limit_buckets.clear()
        api._rate_limit_max = 2
        api._rate_limit_window = 60

        # Client A uses its quota
        with api.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.3'}
        ):
            api._check_rate_limit()
            api._check_rate_limit()
            assert api._check_rate_limit() is False

        # Client B still has quota
        with api.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.4'}
        ):
            assert api._check_rate_limit() is True

    def test_expired_entries_are_cleaned(self):
        """Entries older than the rate limit window should be pruned,
        allowing new requests."""
        from src.integration import api

        api._rate_limit_buckets.clear()
        api._rate_limit_max = 2
        api._rate_limit_window = 1  # 1 second window for fast test

        with api.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': '10.0.0.5'}
        ):
            api._check_rate_limit()
            api._check_rate_limit()
            assert api._check_rate_limit() is False

            # Wait for the window to expire
            time.sleep(1.1)

            # Now should be allowed again
            assert api._check_rate_limit() is True
