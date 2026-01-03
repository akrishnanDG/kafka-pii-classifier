# Integration Module

This module provides a REST API for triggering batch classification from external systems.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/classify` | POST | Classify specific topics |
| `/api/v1/classify/all` | POST | Classify all topics |
| `/api/v1/status` | GET | Get agent status |
| `/api/v1/config` | GET | Get configuration (non-sensitive) |

## Usage

### Start API Server

```bash
pii-classifier -c config/config.yaml --api-server
```

### Example API Calls

```bash
# Health check
curl http://localhost:8000/health

# Classify a topic
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"topic": "user-events", "priority": "high"}'

# Classify all topics
curl -X POST http://localhost:8000/api/v1/classify/all
```

## Configuration

```yaml
integration:
  api:
    enabled: true
    host: "0.0.0.0"
    port: 8000
    debug: false
```
