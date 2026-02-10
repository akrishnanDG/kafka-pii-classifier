# PII Classification Agent

Automatically detect and classify PII (Personally Identifiable Information) in Kafka topics using pattern matching and optional local LLM analysis. Supports schema tagging, streaming, and batch modes.

## Features

- **Pattern Detection**: Fast regex-based detection for emails, SSNs, credit cards, phone numbers, IP addresses, and more
- **Local LLM Detection**: Optional Ollama integration for privacy-preserving schema-level analysis
- **Schema Tagging**: Automatically annotates AVRO schema fields with PII tags in Schema Registry
- **Streaming & Batch Modes**: Real-time processing with reconnect/circuit breaker, or scheduled batch analysis
- **REST API**: Production-ready (waitress WSGI) with API key auth, rate limiting, and metrics
- **Structured Logging**: Optional JSON log format (`--json-logs`) for log aggregation systems
- **HTML/JSON Reports**: PII sample values are automatically masked to prevent data leakage
- **Docker Ready**: Dockerfile and docker-compose included for all deployment modes

## Supported PII Types (20)

### Core Types (Enabled by Default)
| Type | Risk | Type | Risk |
|------|------|------|------|
| SSN | High | EMAIL | Medium |
| PHONE_NUMBER | Medium | ADDRESS | Medium |
| CREDIT_CARD | High | DATE_OF_BIRTH | Medium |
| PASSPORT | High | DRIVER_LICENSE | High |
| IP_ADDRESS | Low | NAME | Medium |

### Additional Types (Disabled by Default)
| Type | Risk | Type | Risk |
|------|------|------|------|
| BANK_ACCOUNT | High | IBAN | High |
| SWIFT_CODE | Medium | AWS_ACCESS_KEY | High |
| AWS_SECRET_KEY | High | ITIN | High |
| NATIONAL_INSURANCE_NUMBER | High | USERNAME | Low |
| PASSWORD | High | MAC_ADDRESS | Low |

## Quick Start

### 1. Install

```bash
pip install -e .
```

Optional providers:
```bash
# Presidio NLP detection (pattern + NLP)
pip install presidio-analyzer spacy
python -m spacy download en_core_web_lg

# Ollama LLM detection (schema-level analysis)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve  # keep running in a separate terminal
```

### 2. Configure

Create a configuration file at `config/config.yaml`:

**Minimal config (local Kafka):**
```yaml
kafka:
  bootstrap_servers: "localhost:9092"
  security_protocol: "PLAINTEXT"

schema_registry:
  url: "http://localhost:8081"
```

**Confluent Cloud config:**
```yaml
kafka:
  bootstrap_servers: "pkc-xxxxx.region.confluent.cloud:9092"
  security_protocol: "SASL_SSL"
  sasl_mechanism: "PLAIN"
  sasl_username: "${KAFKA_API_KEY}"
  sasl_password: "${KAFKA_API_SECRET}"

schema_registry:
  url: "https://psrc-xxxxx.region.confluent.cloud"
  api_key: "${SR_API_KEY}"
  api_secret: "${SR_API_SECRET}"
```

Environment variables (`${VAR}`) are automatically substituted. Use `${?VAR}` for optional variables.

### 3. Run

```bash
# Show help
pii-classifier --help

# Dry run - analyze all topics without making changes
pii-classifier -c config/config.yaml --all-topics --dry-run

# Analyze specific topics
pii-classifier -c config/config.yaml -t topic1 -t topic2

# Analyze and tag schemas with PII annotations
pii-classifier -c config/config.yaml --all-topics --enable-tagging

# Custom sampling rate (percentage of messages to sample)
pii-classifier -c config/config.yaml --all-topics --sample-percentage 10
```

## Usage Examples

### Batch Analysis (default)
```bash
pii-classifier -c config/config.yaml --all-topics
pii-classifier -c config/config.yaml -t user-events --log-level DEBUG
```

### Schema Tagging
```bash
# Tag AVRO schemas with PII field annotations in Schema Registry
pii-classifier -c config/config.yaml --all-topics --enable-tagging

# Tags are added as 'doc' annotations: "PII: EMAIL (confidence: 0.95)"
# Original schemas are backed up to schema_backups/ before modification
```

### Streaming Mode
```bash
pii-classifier -c config/config.yaml --streaming
pii-classifier -c config/config.yaml --streaming --offset-reset earliest
pii-classifier -c config/config.yaml --streaming --offset-storage ./offsets.json
```

Features automatic reconnect with exponential backoff and circuit breaker (stops after 100 consecutive handler failures).

### Continuous Monitoring
```bash
pii-classifier -c config/config.yaml --monitor --monitor-interval 3600
```

### API Server
```bash
# Start production API server (waitress WSGI, binds to 127.0.0.1:8000)
pii-classifier -c config/config.yaml --api-server

# With structured JSON logs for production
pii-classifier -c config/config.yaml --api-server --json-logs

# Trigger classification via HTTP
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"topic": "user-events"}'

# Check metrics
curl http://localhost:8000/metrics -H "X-API-Key: your-api-key"
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check (returns 503 when unhealthy) |
| `/metrics` | GET | Yes | Request counts, classification stats, uptime |
| `/api/v1/classify` | POST | Yes | Classify specific topic(s) |
| `/api/v1/classify/all` | POST | Yes | Classify all topics |
| `/api/v1/status` | GET | Yes | Agent status and last run info |
| `/api/v1/config` | GET | Yes | Configuration (sensitive values masked) |

Set `PII_CLASSIFIER_API_KEY` environment variable or `integration.api.api_key` in config for authentication. Classify endpoints are rate-limited (30 req/60s default, configurable).

## Configuration

### PII Detection Providers

| Provider | Type | Cost | Privacy | Best For |
|----------|------|------|---------|----------|
| `pattern` | Regex | Free | Local | Fast detection of structured PII (default) |
| `llm_agent` | Ollama (local) | Free | Local | Schema-level analysis, no data leaves environment |
| `presidio` | NLP | Free | Local | Context-aware detection with spaCy |
| `openai` | Cloud API | Pay-per-use | Cloud | GPT-4 powered detection |
| `anthropic` | Cloud API | Pay-per-use | Cloud | Claude powered detection |
| `gemini` | Cloud API | Pay-per-use | Cloud | Gemini powered detection |
| `aws` | Cloud API | Pay-per-use | Cloud | AWS Comprehend |
| `gcp` | Cloud API | Pay-per-use | Cloud | Google Cloud DLP |
| `azure` | Cloud API | Pay-per-use | Cloud | Azure Text Analytics |

> **Data Privacy Notice**: Cloud LLM providers (`openai`, `anthropic`, `gemini`) send field names and sample values to external APIs. Ensure this complies with your data protection obligations (GDPR, CCPA, HIPAA). For privacy-sensitive environments, use `pattern` or `llm_agent` (Ollama) which keep all data local. Set `data_privacy_acknowledged: true` in provider config to confirm compliance.

```yaml
pii_detection:
  # Pattern-only (default, no external deps):
  providers:
    - "pattern"

  # Pattern + local LLM (requires Ollama, no data leaves environment):
  # providers:
  #   - "pattern"
  #   - "llm_agent"
  # providers_config:
  #   llm_agent:
  #     base_url: "http://localhost:11434"
  #     model: "llama3.2"

  # Pattern + OpenAI (cloud — review GDPR compliance):
  # providers:
  #   - "pattern"
  #   - "openai"
  # providers_config:
  #   openai:
  #     api_key: "${OPENAI_API_KEY}"
  #     model: "gpt-4o-mini"
  #     data_privacy_acknowledged: true

  # Pattern + Anthropic Claude (cloud — review GDPR compliance):
  # providers:
  #   - "pattern"
  #   - "anthropic"
  # providers_config:
  #   anthropic:
  #     api_key: "${ANTHROPIC_API_KEY}"
  #     model: "claude-sonnet-4-20250514"
  #     data_privacy_acknowledged: true

  # Pattern + Google Gemini (cloud — review GDPR compliance):
  # providers:
  #   - "pattern"
  #   - "gemini"
  # providers_config:
  #   gemini:
  #     api_key: "${GEMINI_API_KEY}"
  #     model: "gemini-2.0-flash"
  #     data_privacy_acknowledged: true

  # Pattern + Presidio NLP (local):
  # providers:
  #   - "pattern"
  #   - "presidio"

  enabled_types:
    - "SSN"
    - "EMAIL"
    - "PHONE_NUMBER"
    - "CREDIT_CARD"
    - "IP_ADDRESS"
    - "NAME"
    - "DATE_OF_BIRTH"
    - "ADDRESS"
    - "PASSPORT"
    - "DRIVER_LICENSE"
```

### Sampling

```yaml
sampling:
  strategy: "percentage"     # or "count", "time_based", "all"
  sample_percentage: 5       # percentage of messages to sample
  max_samples_per_partition: 1000
```

### Schema Tagging

```yaml
tagging:
  enabled: false             # or use --enable-tagging flag
  tag_format: "metadata"     # "metadata" (doc + REST API) or "description" (doc only)
  create_backup: true        # backup original schema before modification
```

When enabled, PII fields are annotated with `doc` attributes (e.g., `"doc": "PII: EMAIL (confidence: 0.95)"`) and a new schema version is registered. Original schemas are backed up to `schema_backups/`.

### Reporting

```yaml
reporting:
  output_format: ["json", "html"]
  output_directory: "./reports"
  include_samples: false     # PII values are masked when true, omitted when false
```

### API Server

```yaml
integration:
  api:
    api_key: "your-secret-key"   # or set PII_CLASSIFIER_API_KEY env var
    rate_limit_max: 30           # max requests per window
    rate_limit_window: 60        # window in seconds
```

See [DOCUMENTATION.md](DOCUMENTATION.md) for the complete configuration reference.

## Docker Deployment

### Build and run with Docker

```bash
# Build the image
docker build -t pii-classifier .

# Run batch analysis
docker run --rm \
  -v ./config:/app/config:ro \
  -v ./reports:/home/appuser/reports \
  pii-classifier -c /app/config/config.yaml --all-topics --json-logs

# Run API server
docker run -d \
  -p 8000:8000 \
  -v ./config:/app/config:ro \
  -e PII_CLASSIFIER_API_KEY=your-secret \
  pii-classifier -c /app/config/config.yaml --api-server --api-host 0.0.0.0 --json-logs
```

### Docker Compose (full stack)

```bash
# Start Kafka + Schema Registry only (for development)
docker compose up -d kafka schema-registry

# Start with API server
docker compose --profile api up -d

# Run batch analysis
docker compose --profile batch run pii-classifier-batch
```

## Local Development

```bash
# Start Kafka + Schema Registry
docker compose up -d kafka schema-registry

# Wait for services, then produce test data
python tests/setup_test_data.py

# Run classifier against test data
pii-classifier -c config/config.yaml --all-topics

# Run with schema tagging
pii-classifier -c config/config.yaml --all-topics --enable-tagging
```

## Architecture

```
+-------------------+
|     main.py       |  CLI Entry Point (click)
+--------+----------+
         |
+--------v----------+
|       Agent       |  Workflow Orchestrator
+--------+----------+
         |
    +----+----+----------+----------+
    v         v          v          v
+--------+ +------+ +--------+ +----------+
| Kafka  | |Schema| |  PII   | | Reporting|
|Consumer| | Reg. | |Detector| | Generator|
+--------+ +------+ +--------+ +----------+
               |          |
          +----v----+ +---v--------+
          | Schema  | | Pattern    |
          | Tagger  | | Presidio   |
          +---------+ | LLM Agent  |
                      | Cloud APIs |
                      +------------+
```

## Reports

Reports are generated in `reports/`:
- `pii_classification_report_YYYYMMDD_HHMMSS.html`
- `pii_classification_report_YYYYMMDD_HHMMSS.json`

PII sample values are automatically masked in reports to prevent data leakage.

## Testing

```bash
# Unit tests (169 tests)
pytest tests/ -m "not integration"

# Integration tests (requires running Kafka + Schema Registry)
pytest tests/ -m integration

# All tests
pytest tests/
```

## Troubleshooting

### Ollama not responding
```bash
curl http://localhost:11434/api/tags  # Check if running
ollama serve                          # Start if not running
ollama list                           # Check installed models
```

### Connection errors
- Verify Kafka/Schema Registry URLs and credentials
- Check network connectivity and firewall rules
- For PLAINTEXT protocol, ensure no SASL settings are configured

### No PII detected
- Check that `enabled_types` includes the PII types you expect
- Increase `sample_percentage` for topics with sparse PII
- Try `--log-level DEBUG` for detailed detection logs

### Schema tagging not working
- Ensure the topic has an AVRO schema registered
- Check logs for compatibility errors — tagging temporarily sets compatibility to NONE
- Backups are saved in `schema_backups/` before any modification

## Documentation

- [DOCUMENTATION.md](DOCUMENTATION.md) - Complete reference and configuration guide

## License

Apache License 2.0 - see [LICENSE](LICENSE)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request
