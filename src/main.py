"""Main entry point for the PII classification agent."""

import re
import signal
import sys
from pathlib import Path
import click
from typing import Optional

from .config.config_loader import load_config
from .utils.logger import setup_logger
from .utils.exceptions import ConfigurationError
from .__version__ import __version__

logger = setup_logger()

BANNER = r"""
  +---------------------------------------------------------+
  |  ___  ___ ___    ___ _            _  __ _                 |
  | | _ \|_ _|_ _|  / __| |__ _ _____(_)/ _(_)___ _ _         |
  | |  _/ | | | |  | (__| / _` (_-<_-< |  _| / -_) '_|        |
  | |_|  |___|___|  \___|_\__,_/__/__/_|_| |_\___|_|          |
  |                                                           |
  |  Detect & classify PII in Kafka topics                    |
  +---------------------------------------------------------+
"""


def print_version(ctx, param, value):
    """Print version and exit."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"pii-classifier version {__version__}")
    ctx.exit()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    '--version', '-V',
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help='Show version and exit'
)
@click.option(
    '--config',
    '-c',
    type=click.Path(exists=True, path_type=Path),
    default=Path('config/config.yaml'),
    help='Path to configuration file'
)
@click.option(
    '--topics',
    '-t',
    multiple=True,
    help='Specific topics to analyze (can be specified multiple times). If not specified, analyzes all topics.'
)
@click.option(
    '--all-topics',
    is_flag=True,
    help='Analyze all topics in the cluster (excludes system topics)'
)
@click.option(
    '--sample-percentage',
    type=float,
    help='Override sample percentage from config'
)
@click.option(
    '--enable-tagging',
    is_flag=True,
    help='Enable schema tagging (default: False)'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Run without making any changes (dry run mode)'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(path_type=Path),
    help='Output directory for reports'
)
@click.option(
    '--log-level',
    type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
    default='INFO',
    help='Logging level'
)
@click.option(
    '--api-server',
    is_flag=True,
    help='Start API server for integration (instead of running batch classification)'
)
@click.option(
    '--api-host',
    default='127.0.0.1',
    help='API server host (default: 127.0.0.1)'
)
@click.option(
    '--api-port',
    type=int,
    default=8000,
    help='API server port (default: 8000)'
)
@click.option(
    '--monitor',
    '--continuous',
    is_flag=True,
    help='Run in continuous monitoring mode (periodically re-analyze topics)'
)
@click.option(
    '--monitor-interval',
    type=int,
    default=3600,
    help='Monitoring interval in seconds (default: 3600 = 1 hour)'
)
@click.option(
    '--streaming',
    is_flag=True,
    help='Run in streaming mode (process messages as they arrive)'
)
@click.option(
    '--offset-reset',
    type=click.Choice(['latest', 'earliest']),
    default='latest',
    help='Offset reset strategy for streaming (default: latest)'
)
@click.option(
    '--offset-storage',
    type=click.Path(path_type=Path),
    help='Path to store offsets for streaming mode'
)
@click.option(
    '--commit-interval',
    type=int,
    default=100,
    help='Commit offsets every N messages in streaming mode (default: 100)'
)
@click.option(
    '--json-logs',
    is_flag=True,
    help='Use structured JSON log format (recommended for production)'
)
def main(
    config: Path,
    topics: tuple,
    all_topics: bool,
    sample_percentage: Optional[float],
    enable_tagging: bool,
    dry_run: bool,
    output: Optional[Path],
    log_level: str,
    api_server: bool,
    api_host: str,
    api_port: int,
    monitor: bool,
    monitor_interval: int,
    streaming: bool,
    offset_reset: str,
    offset_storage: Optional[Path],
    commit_interval: int,
    json_logs: bool
):
    """
    PII Classification Agent - Automatically detect and classify PII in Kafka topics.

    Can run in four modes:
    1. Batch classification mode (default) - Runs batch analysis once
    2. API server mode (--api-server) - Starts REST API for integration
    3. Continuous monitoring mode (--monitor) - Periodically re-analyzes topics
    4. Streaming mode (--streaming) - Process messages as they arrive in real-time
    """
    try:
        # Setup logging
        global logger
        logger = setup_logger(log_level=log_level, json_format=json_logs)

        sys.stdout.flush()

        # Check if API server mode
        if api_server:
            print("\n" + "="*80, flush=True)
            print("PII CLASSIFICATION AGENT - API SERVER MODE", flush=True)
            print("="*80, flush=True)
            print(f"Configuration: {config}", flush=True)
            print(f"API Server: http://{api_host}:{api_port}", flush=True)
            print(f"Log Level: {log_level}", flush=True)
            print("="*80 + "\n", flush=True)

            logger.info("Starting PII Classification Agent in API server mode")
            logger.info(f"API will be available at http://{api_host}:{api_port}")

            # Start API server
            from .integration.api import run_api_server
            run_api_server(
                config_path=config,
                host=api_host,
                port=api_port,
                debug=False
            )
            return

        # Batch classification mode (default)
        click.echo(click.style(BANNER, fg='cyan'))
        click.echo(f"  Version: {__version__}")
        click.echo(f"  Config:  {config}")
        click.echo(f"  Mode:    {'Dry Run' if dry_run else 'Analysis'}")
        click.echo("")

        logger.info("Starting PII Classification Agent")
        logger.info(f"Configuration file: {config}")
        sys.stdout.flush()

        # Load configuration
        print("Loading configuration...", flush=True)
        try:
            config_dict = load_config(config)
            print("Configuration loaded successfully", flush=True)
        except ConfigurationError as e:
            print(f"Configuration error: {e}", flush=True)
            logger.error(f"Configuration error: {e}")
            sys.exit(1)

        # Save CLI topics for later override
        cli_topics = list(topics) if topics else None

        # If --all-topics flag is set, clear topics list in config
        if all_topics:
            config_dict['topics'] = []
            logger.info("--all-topics flag set: will analyze all topics in cluster")

        if sample_percentage is not None:
            config_dict.setdefault('sampling', {})['sample_percentage'] = sample_percentage

        if enable_tagging:
            config_dict.setdefault('tagging', {})['enabled'] = True

        if dry_run:
            config_dict.setdefault('tagging', {})['enabled'] = False
            logger.info("Running in DRY-RUN mode (no changes will be made)")

        if output:
            config_dict.setdefault('reporting', {})['output_directory'] = str(output)

        # Initialize and run the agent
        print("Initializing agent...", flush=True)
        from .agent import PIIClassificationAgent

        agent = PIIClassificationAgent(config_dict)
        print("Agent initialized", flush=True)

        # Determine topics to analyze
        target_topics = _resolve_topics(config_dict, cli_topics, all_topics, agent)

        if not target_topics:
            logger.error("No topics to analyze")
            sys.exit(1)

        print(f"\n{'='*80}", flush=True)
        print(f"STARTING ANALYSIS", flush=True)
        print(f"{'='*80}", flush=True)
        print(f"Topics to analyze: {len(target_topics)}", flush=True)
        if len(target_topics) <= 20:
            print(f"Topics: {', '.join(target_topics)}", flush=True)
        else:
            print(f"First 20 topics: {', '.join(target_topics[:20])}... (+{len(target_topics) - 20} more)", flush=True)
        print(f"{'='*80}\n", flush=True)

        logger.info(f"Will analyze {len(target_topics)} topic(s)")

        # Check if streaming mode
        if streaming:
            print("\n" + "="*80, flush=True)
            print("PII CLASSIFICATION AGENT - STREAMING MODE", flush=True)
            print("="*80, flush=True)
            print(f"Configuration: {config}", flush=True)
            print(f"Topics: {target_topics if target_topics else 'All topics'}", flush=True)
            print(f"Offset Reset: {offset_reset}", flush=True)
            print(f"Log Level: {log_level}", flush=True)
            print("="*80 + "\n", flush=True)

            logger.info("Starting PII Classification Agent in streaming mode")

            # Start streaming (reuse existing agent, don't create a second one)
            streaming_consumer = agent.run_streaming(
                topics=target_topics,
                offset_reset=offset_reset,
                offset_storage_path=offset_storage,
                commit_interval=commit_interval,
                enable_tagging=enable_tagging
            )

            # Register SIGTERM handler for graceful shutdown
            def _sigterm_handler(signum, frame):
                print("\nReceived SIGTERM, shutting down...", flush=True)
                streaming_consumer.stop()

            signal.signal(signal.SIGTERM, _sigterm_handler)

            try:
                # Start streaming (blocks until stopped)
                streaming_consumer.start()
            except KeyboardInterrupt:
                print("\nStopping streaming consumer...", flush=True)
                streaming_consumer.stop()
                print("Streaming stopped gracefully", flush=True)

            return

        # Check if continuous monitoring mode
        if monitor:
            print("\n" + "="*80)
            print("CONTINUOUS MONITORING MODE")
            print("="*80)
            print(f"Monitoring interval: {monitor_interval} seconds ({monitor_interval/60:.1f} minutes)")
            print(f"Topics to monitor: {len(target_topics)}")
            print(f"Press Ctrl+C to stop monitoring\n")
            print("="*80 + "\n", flush=True)

            import time
            from datetime import datetime, timedelta

            iteration = 0
            try:
                while True:
                    iteration += 1
                    print(f"\n{'='*80}")
                    print(f"MONITORING CYCLE #{iteration}")
                    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"{'='*80}\n", flush=True)

                    # Create a fresh agent each cycle to avoid stale connections
                    cycle_agent = PIIClassificationAgent(config_dict)
                    print("Starting analysis...\n", flush=True)
                    results = cycle_agent.run(target_topics)
                    print("\n", flush=True)

                    # Print summary
                    topics_with_pii = [r for r in results['topics_analyzed'] if r.get('pii_fields_found', 0) > 0]
                    if topics_with_pii:
                        print(f"\nFound PII in {len(topics_with_pii)} topic(s):")
                        for topic_result in topics_with_pii:
                            topic_name = topic_result.get('topic', 'Unknown')
                            pii_fields = topic_result.get('pii_fields_found', 0)
                            print(f"  - {topic_name}: {pii_fields} PII field(s)")
                    else:
                        print("No PII detected in this cycle")

                    # Wait for next cycle
                    next_cycle_time = datetime.now() + timedelta(seconds=monitor_interval)
                    print(f"\nWaiting {monitor_interval} seconds until next cycle...")
                    print(f"   Next cycle at: {next_cycle_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print("   (Press Ctrl+C to stop)\n", flush=True)

                    time.sleep(monitor_interval)

            except KeyboardInterrupt:
                print("\n\n" + "="*80)
                print("MONITORING STOPPED")
                print("="*80)
                print(f"Total cycles completed: {iteration}")
                print("="*80 + "\n", flush=True)
                logger.info(f"Continuous monitoring stopped after {iteration} cycles")
                return

        # Single run mode (default)
        print("Starting analysis...\n", flush=True)
        results = agent.run(target_topics)
        print("\n", flush=True)

        # Separate topics into categories
        topics_with_data = []
        topics_with_pii = []
        empty_topics = []

        for topic_result in results['topics_analyzed']:
            samples = topic_result.get('samples', 0)
            pii_fields = topic_result.get('pii_fields_found', 0)

            if pii_fields > 0:
                topics_with_pii.append(topic_result)
            elif samples > 0:
                topics_with_data.append(topic_result)
            else:
                empty_topics.append(topic_result)

        # Print summary with clear formatting
        print("\n" + "="*80)
        print("ANALYSIS SUMMARY")
        print("="*80)
        print(f"Topics Analyzed: {len(results['topics_analyzed'])}")
        print(f"  - Topics with PII: {len(topics_with_pii)}")
        print(f"  - Topics with data (no PII): {len(topics_with_data)}")
        print(f"  - Empty topics: {len(empty_topics)}")
        print(f"\nTotal Fields Classified: {results['total_fields_classified']}")
        print(f"Total PII Fields Found: {results['total_pii_fields']}")

        if results['errors']:
            print(f"\nErrors: {len(results['errors'])}")
            for error in results['errors']:
                print(f"  - {error}")

        # Show topics with PII prominently
        if topics_with_pii:
            print("\n" + "="*80)
            print("TOPICS WITH PII DETECTED")
            print("="*80)

            for topic_result in topics_with_pii:
                topic_name = topic_result.get('topic', 'Unknown')
                samples = topic_result.get('samples', 0)
                pii_fields = topic_result.get('pii_fields_found', 0)
                schemaless = topic_result.get('schemaless', False)

                print(f"\nTopic: {topic_name}")
                print(f"   Samples: {samples} | PII Fields: {pii_fields} | Schemaless: {'Yes' if schemaless else 'No'}")

                classifications = topic_result.get('classifications', {})
                if classifications:
                    print(f"   Fields with PII:")
                    for field_path, cls in list(classifications.items())[:10]:
                        tags = ', '.join(cls.get('tags', [])[:3])
                        conf = cls.get('confidence', 0)
                        rate = cls.get('detection_rate', 0)
                        print(f"     - {field_path}: {tags} (conf: {conf:.2f}, rate: {rate:.1%})")
                    if len(classifications) > 10:
                        print(f"     ... and {len(classifications) - 10} more fields")

        # Show topics with data but no PII (brief)
        if topics_with_data:
            print("\n" + "-"*80)
            print(f"TOPICS WITH DATA (NO PII) - {len(topics_with_data)} topics")
            print("-"*80)
            for topic_result in topics_with_data[:20]:
                topic_name = topic_result.get('topic', 'Unknown')
                samples = topic_result.get('samples', 0)
                print(f"  - {topic_name}: {samples} samples")
            if len(topics_with_data) > 20:
                print(f"  ... and {len(topics_with_data) - 20} more topics")

        # Show empty topics (collapsed)
        if empty_topics:
            print("\n" + "-"*80)
            print(f"EMPTY TOPICS - {len(empty_topics)} topics")
            print("-"*80)
            if len(empty_topics) <= 50:
                for i, topic_result in enumerate(empty_topics):
                    topic_name = topic_result.get('topic', 'Unknown')
                    print(f"  {topic_name}", end="")
                    if (i + 1) % 5 == 0:
                        print()
                    elif i < len(empty_topics) - 1:
                        print(" | ", end="")
                if len(empty_topics) % 5 != 0:
                    print()
            else:
                for i, topic_result in enumerate(empty_topics[:30]):
                    topic_name = topic_result.get('topic', 'Unknown')
                    print(f"  {topic_name}", end="")
                    if (i + 1) % 5 == 0:
                        print()
                    elif i < 29:
                        print(" | ", end="")
                print(f"\n  ... and {len(empty_topics) - 30} more empty topics")

        # Show report files
        if results.get('report_files'):
            print("\n" + "="*80)
            print("REPORTS GENERATED")
            print("="*80)
            for report_file in results['report_files']:
                print(f"  {report_file}")

        print("\n" + "="*80)
        print("ANALYSIS COMPLETE!")
        print("="*80 + "\n")

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


def _resolve_topics(config_dict, cli_topics, all_topics_flag, agent):
    """Resolve which topics to analyze from config, CLI args, and discovery.

    Returns:
        List of topic names to analyze.
    """
    # CLI topics take highest priority
    if cli_topics:
        logger.info(f"Using topics from command line: {cli_topics}")
        return cli_topics

    # Get topics from config (can be a list or a dict with exclude_patterns)
    topics_config = config_dict.get('topics', [])

    if isinstance(topics_config, list) and topics_config and not all_topics_flag:
        # Explicit topic list in config
        return topics_config

    # Discover all topics from Kafka
    print("Connecting to Kafka to discover topics...", flush=True)
    logger.info("Analyzing all topics in cluster")
    agent.kafka_consumer.connect()
    print("Connected to Kafka", flush=True)
    print("Discovering topics...", flush=True)
    discovered_topics = agent.kafka_consumer.list_topics()
    print(f"Found {len(discovered_topics)} topics in cluster", flush=True)

    # Get exclude patterns
    if isinstance(topics_config, dict):
        exclude_patterns = topics_config.get('exclude_patterns', [])
    else:
        exclude_patterns = []

    # Default exclusions if not specified
    if not exclude_patterns:
        exclude_patterns = [
            '^_',
            '__consumer_offsets',
            '__transaction_state',
        ]

    # Filter out system topics
    filtered_topics = []
    for topic_name in discovered_topics:
        exclude = False
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, topic_name):
                    exclude = True
                    break
            except re.error:
                if pattern in topic_name:
                    exclude = True
                    break
        if not exclude:
            filtered_topics.append(topic_name)

    print(f"{len(filtered_topics)} topics to analyze (excluded {len(discovered_topics) - len(filtered_topics)} system topics)", flush=True)
    logger.info(
        f"Found {len(filtered_topics)} topics to analyze "
        f"(excluded {len(discovered_topics) - len(filtered_topics)} system topics)"
    )
    return filtered_topics


# Entry point for CLI
if __name__ == '__main__':
    main()
