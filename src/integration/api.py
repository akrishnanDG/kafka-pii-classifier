"""
API endpoints for external system integration.

This module provides REST API endpoints that allow external systems
to trigger batch classification and query results.

Uses waitress as the production WSGI server instead of Flask's
built-in development server.
"""

import copy
import logging
import os
import secrets
import time
from collections import defaultdict
from functools import wraps
from threading import Lock
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from datetime import datetime

from ..agent import PIIClassificationAgent
from ..config.config_loader import load_config
from pathlib import Path

logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Global state
_agent: Optional[PIIClassificationAgent] = None
_config_path: Optional[Path] = None
_api_key: Optional[str] = None
_classify_lock = Lock()

# Metrics tracking
_metrics = {
    'requests_total': 0,
    'requests_by_endpoint': defaultdict(int),
    'requests_errors': 0,
    'classifications_total': 0,
    'topics_analyzed_total': 0,
    'pii_fields_found_total': 0,
    'last_classification_at': None,
    'uptime_started_at': None,
}
_metrics_lock = Lock()

# Rate limiting
_rate_limit_window = 60  # seconds
_rate_limit_max = 30  # max requests per window
_rate_limit_buckets: Dict[str, list] = defaultdict(list)
_rate_limit_lock = Lock()


def _track_request(endpoint: str):
    """Record a request for metrics."""
    with _metrics_lock:
        _metrics['requests_total'] += 1
        _metrics['requests_by_endpoint'][endpoint] += 1


def _track_error():
    """Record an error for metrics."""
    with _metrics_lock:
        _metrics['requests_errors'] += 1


def _track_classification(results: dict):
    """Record classification results for metrics."""
    with _metrics_lock:
        _metrics['classifications_total'] += 1
        _metrics['topics_analyzed_total'] += len(results.get('topics_analyzed', []))
        _metrics['pii_fields_found_total'] += results.get('total_pii_fields', 0)
        _metrics['last_classification_at'] = datetime.now().isoformat()


def _check_rate_limit() -> bool:
    """Check if the client has exceeded the rate limit.

    Returns:
        True if the request is allowed, False if rate-limited.
    """
    client_ip = request.remote_addr or 'unknown'
    now = time.monotonic()
    with _rate_limit_lock:
        # Clean old entries
        _rate_limit_buckets[client_ip] = [
            t for t in _rate_limit_buckets[client_ip]
            if now - t < _rate_limit_window
        ]
        if len(_rate_limit_buckets[client_ip]) >= _rate_limit_max:
            return False
        _rate_limit_buckets[client_ip].append(now)
        return True


def _check_api_key(f):
    """Decorator to enforce API key authentication when configured."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _api_key:
            provided = request.headers.get('X-API-Key', '')
            if not secrets.compare_digest(provided, _api_key):
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def _rate_limited(f):
    """Decorator to enforce rate limiting on classify endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _check_rate_limit():
            return jsonify({
                'success': False,
                'error': f'Rate limit exceeded ({_rate_limit_max} requests per {_rate_limit_window}s)'
            }), 429
        return f(*args, **kwargs)
    return decorated


def initialize_api(config_path: Path):
    """Initialize the API with configuration."""
    global _agent, _config_path, _api_key, _rate_limit_max, _rate_limit_window

    _config_path = config_path
    config = load_config(config_path)
    _agent = PIIClassificationAgent(config)

    # API key from config or environment variable
    integration_config = config.get('integration', {}).get('api', {})
    _api_key = integration_config.get('api_key') or os.environ.get('PII_CLASSIFIER_API_KEY')
    if not _api_key:
        logger.warning(
            "No API key configured. Set 'integration.api.api_key' in config "
            "or PII_CLASSIFIER_API_KEY env var. API is unauthenticated."
        )

    # Rate limit config
    _rate_limit_max = integration_config.get('rate_limit_max', 30)
    _rate_limit_window = integration_config.get('rate_limit_window', 60)

    with _metrics_lock:
        _metrics['uptime_started_at'] = datetime.now().isoformat()

    logger.info("Integration API initialized")


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with degradation states."""
    _track_request('health')

    if _agent is None:
        return jsonify({
            'status': 'unhealthy',
            'reason': 'agent not initialized',
            'service': 'pii-classification-agent',
            'timestamp': datetime.now().isoformat()
        }), 503

    return jsonify({
        'status': 'healthy',
        'service': 'pii-classification-agent',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/metrics', methods=['GET'])
@_check_api_key
def get_metrics():
    """Prometheus-compatible metrics endpoint (JSON format)."""
    _track_request('metrics')

    with _metrics_lock:
        snapshot = {
            'requests_total': _metrics['requests_total'],
            'requests_by_endpoint': dict(_metrics['requests_by_endpoint']),
            'requests_errors': _metrics['requests_errors'],
            'classifications_total': _metrics['classifications_total'],
            'topics_analyzed_total': _metrics['topics_analyzed_total'],
            'pii_fields_found_total': _metrics['pii_fields_found_total'],
            'last_classification_at': _metrics['last_classification_at'],
            'uptime_started_at': _metrics['uptime_started_at'],
        }

    snapshot['timestamp'] = datetime.now().isoformat()
    return jsonify(snapshot)


@app.route('/api/v1/classify', methods=['POST'])
@_check_api_key
@_rate_limited
def classify_topic():
    """Trigger batch classification for one or more topics."""
    _track_request('classify')

    if _agent is None:
        return jsonify({
            'success': False,
            'error': 'Agent not initialized'
        }), 500

    try:
        data = request.get_json() or {}

        if 'topic' in data:
            topics = [data['topic']]
        elif 'topics' in data:
            topics = data['topics']
        else:
            return jsonify({
                'success': False,
                'error': 'Missing "topic" or "topics" in request body'
            }), 400

        priority = data.get('priority', 'normal')
        enable_tagging = data.get('enable_tagging', False)

        with _classify_lock:
            original_tagging = _agent.config.get('tagging', {}).get('enabled', False)
            if enable_tagging:
                _agent.config.setdefault('tagging', {})['enabled'] = True

            try:
                results = _agent.run(topics=topics)
                _track_classification(results)

                return jsonify({
                    'success': True,
                    'priority': priority,
                    'topics_analyzed': len(results.get('topics_analyzed', [])),
                    'total_fields_classified': results.get('total_fields_classified', 0),
                    'total_pii_fields': results.get('total_pii_fields', 0),
                    'errors': results.get('errors', []),
                    'results': results.get('topics_analyzed', []),
                    'timestamp': datetime.now().isoformat()
                })
            finally:
                _agent.config.setdefault('tagging', {})['enabled'] = original_tagging

    except Exception as e:
        _track_error()
        logger.error(f"Error in classify_topic: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/classify/all', methods=['POST'])
@_check_api_key
@_rate_limited
def classify_all_topics():
    """Trigger batch classification for all topics."""
    _track_request('classify_all')

    if _agent is None:
        return jsonify({
            'success': False,
            'error': 'Agent not initialized'
        }), 500

    try:
        data = request.get_json() or {}
        enable_tagging = data.get('enable_tagging', False)

        with _classify_lock:
            original_tagging = _agent.config.get('tagging', {}).get('enabled', False)
            if enable_tagging:
                _agent.config.setdefault('tagging', {})['enabled'] = True

            try:
                results = _agent.run(topics=None)
                _track_classification(results)

                return jsonify({
                    'success': True,
                    'topics_analyzed': len(results.get('topics_analyzed', [])),
                    'total_fields_classified': results.get('total_fields_classified', 0),
                    'total_pii_fields': results.get('total_pii_fields', 0),
                    'errors': results.get('errors', []),
                    'timestamp': datetime.now().isoformat()
                })
            finally:
                _agent.config.setdefault('tagging', {})['enabled'] = original_tagging

    except Exception as e:
        _track_error()
        logger.error(f"Error in classify_all_topics: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/status', methods=['GET'])
@_check_api_key
def get_status():
    """Get current status of the classification agent."""
    _track_request('status')

    with _metrics_lock:
        last_run = _metrics['last_classification_at']
        total_runs = _metrics['classifications_total']

    return jsonify({
        'status': 'ready' if _agent is not None else 'not_initialized',
        'config_loaded': _config_path is not None and _config_path.exists(),
        'agent_initialized': _agent is not None,
        'classifications_run': total_runs,
        'last_classification_at': last_run,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/v1/config', methods=['GET'])
@_check_api_key
def get_config():
    """Get current configuration (non-sensitive fields only)."""
    _track_request('config')

    if _agent is None:
        return jsonify({'error': 'Agent not initialized'}), 500

    config = copy.deepcopy(_agent.config)
    sensitive_keys = ['password', 'secret', 'api_key', 'api_secret', 'token', 'credential']
    _mask_sensitive(config, sensitive_keys)
    return jsonify(config)


def _mask_sensitive(d: dict, sensitive_keys: list):
    """Recursively mask sensitive values in a dictionary."""
    for key in list(d.keys()):
        if isinstance(d[key], dict):
            _mask_sensitive(d[key], sensitive_keys)
        elif isinstance(d[key], str) and any(s in key.lower() for s in sensitive_keys):
            d[key] = '***'


def run_api_server(config_path: Path, host: str = '127.0.0.1', port: int = 8000, debug: bool = False):
    """
    Run the integration API server using waitress (production WSGI).

    Args:
        config_path: Path to configuration file
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to
        debug: Ignored (kept for interface compatibility)
    """
    initialize_api(config_path)

    logger.info(f"Starting production API server on {host}:{port} (waitress)")
    print(f"API server listening on http://{host}:{port}", flush=True)
    print(f"Endpoints: /health, /metrics, /api/v1/classify, /api/v1/status", flush=True)

    from waitress import serve
    serve(app, host=host, port=port, threads=4, channel_timeout=120)


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.integration.api <config_path> [host] [port]")
        sys.exit(1)

    config_path = Path(sys.argv[1])
    host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8000

    run_api_server(config_path, host=host, port=port)
