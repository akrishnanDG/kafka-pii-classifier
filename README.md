# PII Classification Agent

Automatically detect and classify PII (Personally Identifiable Information) in Kafka topics using local LLM.

## Features

- **Local LLM Detection**: Uses Ollama for privacy-preserving PII detection - no data leaves your environment
- **Schema-Level Analysis**: Analyzes field names + samples in 1 LLM call per topic (100x faster than per-field)
- **Pattern Detection**: Fast regex fallback for obvious PII (emails, SSNs, credit cards)
- **Schema Registry Integration**: Automatic schema tagging with PII metadata
- **Streaming & Batch Modes**: Real-time or scheduled analysis
- **REST API**: Trigger classification from external systems

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
# Install the CLI tool
pip install -e .

# Install Ollama (local LLM)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

Start Ollama server (in a separate terminal):
```bash
ollama serve
```

### 2. Configure

```bash
cp config/config.yaml.example config/config.yaml
# Edit with your Kafka and Schema Registry credentials
```

Minimal config:
```yaml
kafka:
  bootstrap_servers: "your-kafka:9092"
  security_protocol: "SASL_SSL"
  sasl_username: "your-api-key"
  sasl_password: "your-api-secret"

schema_registry:
  url: "https://your-schema-registry"
  api_key: "your-api-key"
  api_secret: "your-api-secret"
```

### 3. Run

```bash
# Show help
pii-classifier --help

# Dry run (no changes)
pii-classifier -c config/config.yaml --all-topics --dry-run

# Analyze specific topics
pii-classifier -c config/config.yaml -t topic1 -t topic2

# Enable schema tagging
pii-classifier -c config/config.yaml --all-topics --enable-tagging

# Streaming mode (real-time)
pii-classifier -c config/config.yaml --streaming
```

## Usage Examples

### Batch Analysis
```bash
# All topics, dry run
pii-classifier -c config/config.yaml --all-topics --dry-run

# Specific topics with debug
pii-classifier -c config/config.yaml -t user-events --log-level DEBUG

# Custom sampling rate
pii-classifier -c config/config.yaml --all-topics --sample-percentage 10
```

### Streaming Mode
```bash
# Stream new messages
pii-classifier -c config/config.yaml --streaming

# Stream with tagging
pii-classifier -c config/config.yaml --streaming --enable-tagging

# Resume from saved offsets
pii-classifier -c config/config.yaml --streaming --offset-storage ./offsets.json

# Process from beginning
pii-classifier -c config/config.yaml --streaming --offset-reset earliest
```

### API Server
```bash
# Start API server
pii-classifier -c config/config.yaml --api-server

# Then trigger via HTTP
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"topic": "user-events"}'
```

## Configuration

### PII Detection (Default: Pattern + LLM)

```yaml
pii_detection:
  # Default: Pattern + LLM Agent
  providers:
    - "pattern"     # Fast regex (emails, SSNs, credit cards)
    - "llm_agent"   # Schema-level LLM analysis
  
  providers_config:
    llm_agent:
      base_url: "http://localhost:11434"
      model: "llama3.2"  # or mistral, gemma2
```

**How it works:**
- **Pattern**: Fast regex catches obvious PII (emails, credit cards, SSNs)
- **LLM Agent**: Analyzes schema (field names + samples) in 1 call per topic

### Optional Providers

```yaml
# Pattern only (no LLM):
providers: ["pattern"]

# Pattern + Presidio (requires: pip install presidio-analyzer spacy):
providers: ["pattern", "presidio"]

# Pattern + Cloud:
providers: ["pattern", "aws"]  # or "gcp", "azure"
```

### Sampling

```yaml
sampling:
  strategy: "percentage"
  sample_percentage: 5
  max_samples_per_partition: 1000
```

### Tagging

```yaml
tagging:
  enabled: false  # Set true to update schemas
  create_backup: true
```

See [config/config.yaml.example](config/config.yaml.example) for full options.

## Architecture

```
┌─────────────────┐
│   main.py       │  CLI Entry Point
└────────┬────────┘
         ▼
┌─────────────────┐
│     Agent       │  Workflow Orchestrator
└────────┬────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    ▼         ▼          ▼          ▼
┌────────┐ ┌──────┐ ┌────────┐ ┌──────────┐
│ Kafka  │ │Schema│ │  PII   │ │ Reporting│
│Consumer│ │Reg.  │ │Detector│ │ Generator│
└────────┘ └──────┘ └────────┘ └──────────┘
```

## Reports

Reports are generated in `reports/`:
- `pii_classification_report_YYYYMMDD_HHMMSS.html`
- `pii_classification_report_YYYYMMDD_HHMMSS.json`

## Troubleshooting

### Ollama not responding
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve

# Verify model is installed
ollama list
```

### Connection errors
- Verify Kafka/Schema Registry URLs and credentials
- Check network connectivity and firewall rules

### No PII detected
- Check sampling configuration
- Verify topics have data
- Try `--log-level DEBUG` for details

### Want to use Presidio instead?
```bash
pip install presidio-analyzer spacy
python -m spacy download en_core_web_lg
# Then set providers: ["pattern", "presidio"] in config
```

## Documentation

- [DOCUMENTATION.md](DOCUMENTATION.md) - Complete reference
- [config/config.yaml.example](config/config.yaml.example) - Configuration reference

## Development

```bash
# Run tests
pytest tests/

# Code quality
black src/
flake8 src/
```

## License

Apache License 2.0 - see [LICENSE](LICENSE)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request
