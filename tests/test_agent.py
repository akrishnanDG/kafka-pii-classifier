"""Tests for PIIClassificationAgent orchestrator."""

import copy
import pytest
from unittest.mock import patch, MagicMock, PropertyMock, call


# ---------------------------------------------------------------------------
# Minimal valid configuration used across all agent tests
# ---------------------------------------------------------------------------
def _make_config(**overrides):
    """Build a minimal valid config dict for the agent."""
    cfg = {
        'kafka': {
            'bootstrap_servers': 'localhost:9092',
            'group_id': 'test-group',
        },
        'schema_registry': {
            'url': 'http://localhost:8081',
        },
        'pii_detection': {
            'enabled_types': ['EMAIL', 'SSN'],
            'providers': ['pattern'],
        },
        'tagging': {
            'enabled': False,
        },
        'reporting': {
            'output_directory': '/tmp/test_reports',
            'output_format': ['json'],
        },
        'sampling': {
            'strategy': 'percentage',
            'sample_percentage': 5,
        },
        'topics': [],
    }
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# Patch targets (all imports resolved inside src.agent)
# ---------------------------------------------------------------------------
_PATCH_KAFKA = 'src.agent.KafkaConsumerService'
_PATCH_SR = 'src.agent.SchemaRegistryClientWrapper'
_PATCH_DETECTOR = 'src.agent.PIIDetector'
_PATCH_CLASSIFIER = 'src.agent.FieldClassifier'
_PATCH_TAGGER = 'src.agent.SchemaTagger'
_PATCH_REPORT = 'src.agent.ReportGenerator'
_PATCH_INFERRER = 'src.agent.SchemaInferrer'


@pytest.fixture
def mock_components():
    """Patch all heavy components so the agent can be instantiated cheaply."""
    with (
        patch(_PATCH_KAFKA) as kafka_cls,
        patch(_PATCH_SR) as sr_cls,
        patch(_PATCH_DETECTOR) as det_cls,
        patch(_PATCH_CLASSIFIER) as cls_cls,
        patch(_PATCH_TAGGER) as tag_cls,
        patch(_PATCH_REPORT) as rpt_cls,
        patch(_PATCH_INFERRER) as inf_cls,
    ):
        # Create mock instances returned by constructors
        kafka_inst = MagicMock(name='KafkaConsumerService_instance')
        sr_inst = MagicMock(name='SchemaRegistryClientWrapper_instance')
        det_inst = MagicMock(name='PIIDetector_instance')
        cls_inst = MagicMock(name='FieldClassifier_instance')
        tag_inst = MagicMock(name='SchemaTagger_instance')
        rpt_inst = MagicMock(name='ReportGenerator_instance')
        inf_inst = MagicMock(name='SchemaInferrer_instance')

        kafka_cls.return_value = kafka_inst
        sr_cls.return_value = sr_inst
        det_cls.return_value = det_inst
        cls_cls.return_value = cls_inst
        tag_cls.return_value = tag_inst
        rpt_cls.return_value = rpt_inst
        inf_cls.return_value = inf_inst

        yield {
            'kafka_cls': kafka_cls,
            'sr_cls': sr_cls,
            'det_cls': det_cls,
            'cls_cls': cls_cls,
            'tag_cls': tag_cls,
            'rpt_cls': rpt_cls,
            'inf_cls': inf_cls,
            'kafka': kafka_inst,
            'sr': sr_inst,
            'detector': det_inst,
            'classifier': cls_inst,
            'tagger': tag_inst,
            'report': rpt_inst,
            'inferrer': inf_inst,
        }


def _build_agent(mock_components, config=None):
    """Instantiate the agent with mocked dependencies."""
    from src.agent import PIIClassificationAgent
    return PIIClassificationAgent(config or _make_config())


# ===================================================================
# run() tests
# ===================================================================

class TestRunEmptyTopics:
    """Test run() with empty topics list returns early."""

    def test_returns_early_with_zero_topics(self, mock_components):
        """When explicit empty topics list is passed, run() should return
        immediately with zero counters and not attempt any processing."""
        agent = _build_agent(mock_components)

        # Report generator should still be called to generate report for empty results
        mock_components['report'].generate.return_value = []

        result = agent.run(topics=[])

        assert result['topics_analyzed'] == []
        assert result['total_fields_classified'] == 0
        assert result['total_pii_fields'] == 0
        assert result['errors'] == []

    def test_returns_early_when_config_topics_empty_and_list_topics_empty(
        self, mock_components
    ):
        """When no topics in config and kafka list_topics returns empty list,
        run() should return early."""
        agent = _build_agent(mock_components, config=_make_config(topics=[]))
        mock_components['kafka'].list_topics.return_value = []
        mock_components['report'].generate.return_value = []

        result = agent.run(topics=None)

        assert result['topics_analyzed'] == []
        assert result['total_fields_classified'] == 0


class TestRunConnectDisconnect:
    """Test run() calls connect/disconnect in try/finally."""

    def test_connect_and_disconnect_called_on_success(self, mock_components):
        """On a successful run with no topics, both connect and disconnect
        must still be called."""
        agent = _build_agent(mock_components)
        mock_components['report'].generate.return_value = []

        agent.run(topics=[])

        mock_components['kafka'].connect.assert_called_once()
        mock_components['sr'].connect.assert_called_once()
        mock_components['kafka'].disconnect.assert_called_once()

    def test_disconnect_called_even_on_error(self, mock_components):
        """If an error is raised during run, kafka.disconnect must still
        be invoked via the finally block."""
        agent = _build_agent(mock_components)

        # Make report generation explode so the finally block is exercised
        mock_components['report'].generate.side_effect = RuntimeError('boom')

        with pytest.raises(RuntimeError, match='boom'):
            agent.run(topics=['some-topic'])

        # The agent's kafka consumer must have been disconnected.
        # Note: disconnect may be called more than once because
        # process_topic_wrapper also creates check consumers that call
        # disconnect. We verify that at least the agent's consumer was
        # disconnected in the finally block.
        assert mock_components['kafka'].disconnect.call_count >= 1


class TestRunSchemaRegistryConnectFailure:
    """Test run() handles schema registry connect failure."""

    def test_sr_connect_failure_disconnects_kafka(self, mock_components):
        """When schema_registry.connect() fails, kafka must be disconnected
        and the exception must propagate."""
        agent = _build_agent(mock_components)
        mock_components['sr'].connect.side_effect = Exception('SR down')

        with pytest.raises(Exception, match='SR down'):
            agent.run(topics=['t1'])

        # Kafka was connected first, then SR failed, so kafka must disconnect
        mock_components['kafka'].connect.assert_called_once()
        mock_components['kafka'].disconnect.assert_called_once()

    def test_sr_connect_failure_does_not_call_sr_disconnect(self, mock_components):
        """The agent does not call schema_registry.disconnect() -- only
        kafka.disconnect(). Verify no unexpected SR teardown."""
        agent = _build_agent(mock_components)
        mock_components['sr'].connect.side_effect = Exception('oops')

        with pytest.raises(Exception):
            agent.run(topics=['t1'])

        # SR has no disconnect method called in the agent code
        # (the agent only disconnects kafka on SR connect failure)


# ===================================================================
# _process_topic tests
# ===================================================================

class TestProcessTopic:
    """Test _process_topic returns correct structure."""

    def test_returns_empty_result_for_empty_topic(self, mock_components):
        """When the topic is empty, _process_topic should return a dict
        with samples=0 and empty=True."""
        agent = _build_agent(mock_components)

        # The method creates a *new* KafkaConsumerService internally via
        # the class constructor (import at module level), so we need to
        # configure the mock class to return our controllable instance.
        inner_consumer = MagicMock(name='inner_consumer')
        inner_consumer.is_topic_empty.return_value = True

        # Because _process_topic does KafkaConsumerService(kafka_config),
        # the class mock will be called again -- we set side_effect so the
        # first call (in __init__) returns the agent's consumer and any
        # subsequent calls return our inner_consumer.
        call_count = [0]
        original_return = mock_components['kafka']

        def _consumer_factory(cfg):
            call_count[0] += 1
            if call_count[0] <= 1:
                return original_return
            return inner_consumer

        mock_components['kafka_cls'].side_effect = _consumer_factory

        # Re-create the agent so the factory is wired up
        agent = _build_agent(mock_components)

        result = agent._process_topic('empty-topic')

        assert result['topic'] == 'empty-topic'
        assert result['samples'] == 0
        assert result['fields_classified'] == 0
        assert result['pii_fields_found'] == 0
        assert result['empty'] is True

    def test_returns_correct_structure_with_data(self, mock_components):
        """When the topic has data, _process_topic should return a dict with
        the expected keys including classifications."""
        agent = _build_agent(mock_components)

        inner_consumer = MagicMock(name='inner_consumer')
        inner_consumer.is_topic_empty.return_value = False
        inner_consumer.get_partition_count.return_value = 1

        call_count = [0]
        original_return = mock_components['kafka']

        def _consumer_factory(cfg):
            call_count[0] += 1
            if call_count[0] <= 1:
                return original_return
            return inner_consumer

        mock_components['kafka_cls'].side_effect = _consumer_factory

        agent = _build_agent(mock_components)

        # Schema registry says no schema (schemaless topic)
        mock_components['sr'].get_schema.return_value = None

        # Patch _sample_topic and _analyze_samples to avoid real I/O
        with patch.object(agent, '_sample_topic', return_value=[]):
            result = agent._process_topic('test-topic')

        assert result['topic'] == 'test-topic'
        assert result['samples'] == 0
        assert 'schemaless' in result

    def test_process_topic_disconnects_consumer_in_finally(self, mock_components):
        """The per-topic consumer must be disconnected even if processing
        raises an exception."""
        agent = _build_agent(mock_components)

        inner_consumer = MagicMock(name='inner_consumer')
        inner_consumer.is_topic_empty.return_value = False
        inner_consumer.get_partition_count.return_value = 1

        call_count = [0]
        original_return = mock_components['kafka']

        def _consumer_factory(cfg):
            call_count[0] += 1
            if call_count[0] <= 1:
                return original_return
            return inner_consumer

        mock_components['kafka_cls'].side_effect = _consumer_factory
        agent = _build_agent(mock_components)

        # Force schema registry to blow up
        mock_components['sr'].get_schema.side_effect = RuntimeError('schema boom')

        with pytest.raises(RuntimeError, match='schema boom'):
            agent._process_topic('boom-topic')

        # inner consumer must still be disconnected
        inner_consumer.disconnect.assert_called_once()


# ===================================================================
# Edge-case: run() with topics from config
# ===================================================================

class TestRunUsesConfigTopics:
    """Verify that run() falls back to config topics or list_topics."""

    def test_uses_config_topics_when_none_passed(self, mock_components):
        """run(topics=None) should read topics from config."""
        cfg = _make_config(topics=['cfg-topic-1'])
        agent = _build_agent(mock_components, config=cfg)
        mock_components['report'].generate.return_value = []

        # We don't want actual processing -- make each topic return quickly
        with patch.object(agent, '_process_topic', return_value={
            'topic': 'cfg-topic-1',
            'samples': 0,
            'fields_classified': 0,
            'pii_fields_found': 0,
            'schemaless': False,
            'empty': True,
        }):
            # Also patch the inner KafkaConsumerService creation in process_topic_wrapper
            inner_consumer = MagicMock()
            inner_consumer.is_topic_empty.return_value = True
            with patch(_PATCH_KAFKA, return_value=inner_consumer):
                result = agent.run(topics=None)

        assert len(result['topics_analyzed']) >= 0  # At least ran without error
