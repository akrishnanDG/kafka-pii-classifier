"""
API endpoints for external system integration.

This module provides REST API endpoints that allow external systems
to trigger batch classification and query results.
"""

import logging
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from datetime import datetime

from ..agent import PIIClassificationAgent
from ..config.config_loader import load_config
from pathlib import Path

logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Global agent instance (initialized on startup)
_agent: Optional[PIIClassificationAgent] = None
_config_path: Optional[Path] = None


def initialize_api(config_path: Path):
    """
    Initialize the API with configuration.
    
    Args:
        config_path: Path to configuration file
    """
    global _agent, _config_path
    
    _config_path = config_path
    config = load_config(config_path)
    _agent = PIIClassificationAgent(config)
    
    logger.info("Integration API initialized")


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'pii-classification-agent',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/v1/classify', methods=['POST'])
def classify_topic():
    """
    Trigger batch classification for one or more topics.
    
    Request body:
    {
        "topic": "topic-name",  # Single topic
        "topics": ["topic1", "topic2"],  # Multiple topics (alternative)
        "priority": "normal",  # "low", "normal", "high"
        "enable_tagging": false  # Whether to enable schema tagging
    }
    
    Returns:
    {
        "success": true,
        "topics_analyzed": [...],
        "total_fields_classified": 10,
        "total_pii_fields": 5,
        "errors": []
    }
    """
    if _agent is None:
        return jsonify({
            'success': False,
            'error': 'Agent not initialized'
        }), 500
    
    try:
        data = request.get_json() or {}
        
        # Get topics
        if 'topic' in data:
            topics = [data['topic']]
        elif 'topics' in data:
            topics = data['topics']
        else:
            return jsonify({
                'success': False,
                'error': 'Missing "topic" or "topics" in request body'
            }), 400
        
        # Get priority (affects processing)
        priority = data.get('priority', 'normal')
        
        # Get tagging setting
        enable_tagging = data.get('enable_tagging', False)
        
        # Temporarily update config if needed
        original_tagging = _agent.config['tagging']['enabled']
        if enable_tagging:
            _agent.config['tagging']['enabled'] = True
        
        try:
            # Run classification
            results = _agent.run(topics=topics)
            
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
            # Restore original tagging setting
            _agent.config['tagging']['enabled'] = original_tagging
            
    except Exception as e:
        logger.error(f"Error in classify_topic: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/classify/all', methods=['POST'])
def classify_all_topics():
    """
    Trigger batch classification for all topics.
    
    Request body:
    {
        "enable_tagging": false,
        "priority": "normal"
    }
    """
    if _agent is None:
        return jsonify({
            'success': False,
            'error': 'Agent not initialized'
        }), 500
    
    try:
        data = request.get_json() or {}
        enable_tagging = data.get('enable_tagging', False)
        
        # Temporarily update config if needed
        original_tagging = _agent.config['tagging']['enabled']
        if enable_tagging:
            _agent.config['tagging']['enabled'] = True
        
        try:
            # Run classification for all topics
            results = _agent.run(topics=None)  # None = all topics
            
            return jsonify({
                'success': True,
                'topics_analyzed': len(results.get('topics_analyzed', [])),
                'total_fields_classified': results.get('total_fields_classified', 0),
                'total_pii_fields': results.get('total_pii_fields', 0),
                'errors': results.get('errors', []),
                'timestamp': datetime.now().isoformat()
            })
        finally:
            # Restore original tagging setting
            _agent.config['tagging']['enabled'] = original_tagging
            
    except Exception as e:
        logger.error(f"Error in classify_all_topics: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/status', methods=['GET'])
def get_status():
    """
    Get current status of the classification agent.
    
    Returns:
    {
        "status": "ready",
        "config_loaded": true,
        "agent_initialized": true
    }
    """
    return jsonify({
        'status': 'ready' if _agent is not None else 'not_initialized',
        'config_loaded': _config_path is not None and _config_path.exists(),
        'agent_initialized': _agent is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/v1/config', methods=['GET'])
def get_config():
    """
    Get current configuration (non-sensitive fields only).
    
    Returns:
    {
        "pii_detection": {
            "providers": ["pattern", "presidio"],
            "enabled_types": [...]
        },
        "sampling": {...},
        ...
    }
    """
    if _agent is None:
        return jsonify({
            'error': 'Agent not initialized'
        }), 500
    
    # Return non-sensitive config
    config = _agent.config.copy()
    
    # Remove sensitive information
    if 'kafka' in config:
        kafka_config = config['kafka'].copy()
        if 'sasl_password' in kafka_config:
            kafka_config['sasl_password'] = '***'
        config['kafka'] = kafka_config
    
    if 'schema_registry' in config:
        sr_config = config['schema_registry'].copy()
        if 'api_secret' in sr_config:
            sr_config['api_secret'] = '***'
        config['schema_registry'] = sr_config
    
    return jsonify(config)


def run_api_server(config_path: Path, host: str = '0.0.0.0', port: int = 8000, debug: bool = False):
    """
    Run the integration API server.
    
    Args:
        config_path: Path to configuration file
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    initialize_api(config_path)
    
    logger.info(f"Starting integration API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    import sys
    from pathlib import Path
    
    if len(sys.argv) < 2:
        print("Usage: python -m src.integration.api <config_path> [host] [port]")
        sys.exit(1)
    
    config_path = Path(sys.argv[1])
    host = sys.argv[2] if len(sys.argv) > 2 else '0.0.0.0'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8000
    
    run_api_server(config_path, host=host, port=port)

