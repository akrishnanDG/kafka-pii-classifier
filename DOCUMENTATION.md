# Complete Documentation

Comprehensive documentation for the PII Classification Agent.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Usage](#usage)
4. [PII Provider Selection](#pii-provider-selection)
5. [Performance Optimization](#performance-optimization)
6. [Run Modes](#run-modes)
7. [Streaming Mode](#streaming-mode-real-time)
8. [API Server](#api-server)
9. [Troubleshooting](#troubleshooting)

---

## Installation

### Quick Installation (LLM-First)

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Ollama (local LLM)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2

# 3. Start Ollama server (keep running in background)
ollama serve
```

This installs everything needed for Pattern + LLM detection (default).

### Optional: Presidio NER

For additional NLP-based detection (uncomment in requirements.txt):
```bash
pip install presidio-analyzer spacy
python -m spacy download en_core_web_lg
```

### Optional: Cloud Providers

**For AWS:**
```bash
pip install boto3
```

**For GCP:**
```bash
pip install google-cloud-dlp
```

**For Azure:**
```bash
pip install azure-ai-textanalytics
```

### About Ollama (Default LLM)

Ollama runs LLMs locally - no data is sent to external services. Recommended models:
- `llama3.2` - Fast and accurate (recommended)
- `mistral` - Good balance of speed and quality
- `gemma2` - Google's open model

### System Requirements

- Python 3.9+
- Kafka cluster access
- Schema Registry access
- 2GB+ RAM (4GB+ recommended)
- Network access to Kafka and Schema Registry

---

## Configuration

### Configuration File Structure

The configuration file (`config/config.yaml`) controls all aspects of the agent:

```yaml
kafka:
  bootstrap_servers: "localhost:9092"
  security_protocol: "PLAINTEXT"  # or "SASL_SSL"
  sasl_mechanism: "PLAIN"  # if using SASL
  sasl_username: "your-api-key"
  sasl_password: "your-api-secret"
  group_id: "pii-classification-agent"

schema_registry:
  url: "http://localhost:8081"
  api_key: ""  # Optional
  api_secret: ""  # Optional

sampling:
  strategy: "percentage"  # or "count", "time_based", "all"
  sample_percentage: 5
  max_samples_per_partition: 1000
  min_samples_per_partition: 10
  use_skip_based_sampling: true  # Performance optimization
  early_termination: true  # Stop when target reached

pii_detection:
  # Default: Pattern + LLM Agent (local LLM via Ollama)
  providers:
    - "pattern"     # Fast regex for obvious PII
    - "llm_agent"   # Schema-level LLM analysis
  
  providers_config:
    llm_agent:
      base_url: "http://localhost:11434"
      model: "llama3.2"
    # Optional providers (uncomment to use):
    # aws:
    #   region_name: "us-east-1"
    # gcp:
    #   project_id: "your-project-id"
    # azure:
    #   endpoint: "https://your-resource.cognitiveservices.azure.com/"
    #   api_key: "your-api-key"
  
  enabled_types:
    - "SSN"
    - "EMAIL"
    - "PHONE_NUMBER"
    - "CREDIT_CARD"
    - "ADDRESS"
    - "NAME"
    - "IP_ADDRESS"
    - "PASSPORT"
    - "DRIVER_LICENSE"
  
  confidence_threshold: 0.6
  require_multiple_detections: true
  min_detection_rate: 0.3

tagging:
  enabled: false  # Set to true to update schemas
  tag_format: "metadata"  # or "description", "custom_property", "tags_api"
  dual_tagging: true
  tag_naming: "PII-{TYPE}"
  create_backup: true

schemaless_data:
  enabled: true
  schema_inference:
    min_samples_for_inference: 10
    max_nesting_depth: 10
    handle_arrays: "aggregate"

reporting:
  output_format: ["html", "json"]
  output_directory: "./reports"
  include_visualizations: true
  include_samples: false

# Performance optimizations
parallel_workers: 20
max_parallel_partitions: 30

# Integration settings
integration:
  api:
    enabled: false
    host: "0.0.0.0"
    port: 8000
    debug: false
```

### Kafka Configuration

**Basic:**
```yaml
kafka:
  bootstrap_servers: "localhost:9092"
  security_protocol: "PLAINTEXT"
  group_id: "pii-classification-agent"
```

**SASL/SSL (Confluent Cloud):**
```yaml
kafka:
  bootstrap_servers: "pkc-xxxxx.region.provider.confluent.cloud:9092"
  security_protocol: "SASL_SSL"
  sasl_mechanism: "PLAIN"
  sasl_username: "your-api-key"
  sasl_password: "your-api-secret"
  group_id: "pii-classification-agent"
```

**Performance Optimizations:**
```yaml
kafka:
  # ... basic config ...
  fetch_min_bytes: 1024
  fetch_max_wait_ms: 100
```

### Schema Registry Configuration

```yaml
schema_registry:
  url: "http://localhost:8081"
  # Optional authentication
  api_key: "your-api-key"
  api_secret: "your-api-secret"
```

### Sampling Configuration

**Percentage Sampling (Recommended):**
```yaml
sampling:
  strategy: "percentage"
  sample_percentage: 5  # 5% of messages
  max_samples_per_partition: 1000
  min_samples_per_partition: 10
  use_skip_based_sampling: true  # Major speedup
  early_termination: true  # Stop when target samples reached
  max_partitions_per_topic: null  # Max partitions to scan (null = all)
                                  # If set, stops after finding samples in X partitions
                                  # Example: 10 means stop after finding samples in 10 partitions
```

**Streaming Mode Configuration:**
```yaml
streaming:
  enabled: false  # Enable via --streaming flag
  offset_reset: "latest"  # "latest" (new messages) or "earliest" (all messages)
  offset_storage_path: "./streaming_offsets.json"  # Optional: Path to store offsets
  commit_interval: 100  # Commit offsets every N messages
  poll_timeout: 1.0  # Polling timeout in seconds
```

**Count-Based Sampling:**
```yaml
sampling:
  strategy: "count"
  max_samples_per_partition: 100
```

**Time-Based Sampling:**
```yaml
sampling:
  strategy: "time_based"
  sample_time_window: "1h"  # Last 1 hour
```

---

## Usage

### Basic Commands

**Analyze all topics:**
```bash
pii-classifier -c config/config.yaml --all-topics
```

**Analyze specific topics:**
```bash
pii-classifier -c config/config.yaml -t topic1 -t topic2
```

**Dry run (no tagging):**
```bash
pii-classifier -c config/config.yaml --all-topics --dry-run
```

**Enable schema tagging:**
```bash
pii-classifier -c config/config.yaml --all-topics --enable-tagging
```

**Note:** If not installed as CLI, use `python -m src.main` instead of `pii-classifier`.

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--version, -V` | Show version and exit | `--version` |
| `--config, -c` | Configuration file path | `-c config/config.yaml` |
| `--topics, -t` | Topics to analyze (repeatable) | `-t topic1 -t topic2` |
| `--all-topics` | Analyze all topics | `--all-topics` |
| `--sample-percentage` | Override sample percentage | `--sample-percentage 10` |
| `--enable-tagging` | Enable schema tagging | `--enable-tagging` |
| `--dry-run` | Run without tagging | `--dry-run` |
| `--output, -o` | Output directory for reports | `-o ./reports` |
| `--log-level` | Log level (DEBUG, INFO, WARNING, ERROR) | `--log-level DEBUG` |
| `--api-server` | Start API server mode | `--api-server` |
| `--api-host` | API server host (default: 0.0.0.0) | `--api-host localhost` |
| `--api-port` | API server port (default: 8000) | `--api-port 8080` |
| `--monitor` | Continuous monitoring mode | `--monitor` |
| `--monitor-interval` | Monitoring interval in seconds | `--monitor-interval 3600` |
| `--streaming` | Streaming mode (real-time) | `--streaming` |
| `--offset-reset` | Offset reset for streaming | `--offset-reset latest` |
| `--offset-storage` | Path to store offsets | `--offset-storage ./offsets.json` |
| `--commit-interval` | Commit every N messages | `--commit-interval 100` |

### Run Modes

**1. Batch Mode (Default):**
```bash
pii-classifier -c config/config.yaml --all-topics
```

**2. API Server Mode:**
```bash
pii-classifier -c config/config.yaml --api-server
```

**3. Continuous Monitoring Mode:**
```bash
pii-classifier -c config/config.yaml --monitor --monitor-interval 3600
```

**4. Streaming Mode (Real-Time):**
```bash
# Stream new messages only (default)
pii-classifier -c config/config.yaml --streaming

# Stream with schema tagging
pii-classifier -c config/config.yaml --streaming --enable-tagging

# Resume from saved offsets
pii-classifier -c config/config.yaml --streaming --offset-storage ./offsets.json

# Process all messages from beginning
pii-classifier -c config/config.yaml --streaming --offset-reset earliest
```

**Note:** If not installed as CLI, use `python -m src.main` instead of `pii-classifier`.

---

## PII Types Supported

The tool can identify the following PII types. The detection capabilities vary by provider, with some types supported by all providers and others only by specific providers.

### Currently Supported PII Types (20 Types)

These 20 PII types are **fully supported** and mapped across all providers:

#### Core PII Types (10 Types)

| PII Type | Description | Risk Level | Pattern | Presidio | AWS | GCP | Azure |
|----------|-------------|------------|---------|----------|-----|-----|-------|
| **SSN** | Social Security Number (US) | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| **EMAIL** | Email Address | Medium | ✅ | ✅ | ✅ | ✅ | ✅ |
| **PHONE_NUMBER** | Phone Number (US & International) | Medium | ✅ | ✅ | ✅ | ✅ | ✅ |
| **ADDRESS** | Physical Address | Medium | ⚠️* | ✅ | ✅ | ✅ | ✅ |
| **CREDIT_CARD** | Credit Card Number (with Luhn validation) | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DATE_OF_BIRTH** | Date of Birth | Medium | ✅ | ✅ | ✅ | ✅ | ✅ |
| **PASSPORT** | Passport Number | High | ❌ | ✅ | ✅ | ✅ | ✅ |
| **DRIVER_LICENSE** | Driver's License Number (US) | High | ❌ | ✅ | ✅ | ✅ | ✅ |
| **IP_ADDRESS** | IP Address (IPv4 & IPv6) | Low | ✅ | ✅ | ✅ | ✅ | ✅ |
| **NAME** | Person Name | Medium | ✅ | ✅ | ✅ | ✅ | ✅ |

*Pattern detector may detect addresses via field name hints but has limited regex patterns.

#### Additional PII Types (10 Types)

| PII Type | Description | Risk Level | Pattern | Presidio | AWS | GCP | Azure |
|----------|-------------|------------|---------|----------|-----|-----|-------|
| **BANK_ACCOUNT** | Bank Account Number | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| **IBAN** | International Bank Account Number | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SWIFT_CODE** | SWIFT/BIC Code | Medium | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS_ACCESS_KEY** | AWS Access Key ID | High | ✅ | ❌ | ✅ | ✅ | ❌ |
| **AWS_SECRET_KEY** | AWS Secret Access Key | High | ✅ | ❌ | ✅ | ✅ | ❌ |
| **ITIN** | Individual Tax ID Number (US) | High | ✅ | ⚠️** | ✅ | ✅ | ✅ |
| **NATIONAL_INSURANCE_NUMBER** | UK National Insurance Number | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| **USERNAME** | Username/Login ID | Low | ❌ | ⚠️** | ✅ | ✅ | ✅ |
| **PASSWORD** | Password | High | ❌ | ⚠️** | ✅ | ✅ | ✅ |
| **MAC_ADDRESS** | MAC Address | Low | ✅ | ⚠️** | ✅ | ✅ | ✅ |

**Presidio may detect these but with different entity names - mapping may need adjustment.

### Additional PII Types Available (Not Yet Mapped)

The following PII types can be detected by cloud providers but are **not currently mapped** in the tool. These can be added upon request:

#### Financial Information
- **Bank Routing Number** - Bank routing/transit numbers
- **Credit/Debit Card CVV** - Card verification value
- **Credit/Debit Card Expiry Date** - Card expiration dates
- **PIN** - Personal Identification Number

#### Technical/Security Information
- **URL** - URLs that may contain sensitive information

#### National Identifiers (Country-Specific)
- **NHS Number** - UK National Health Service Number
- **Social Insurance Number** - Canadian SIN
- **Health Number** - Canadian health insurance number
- **Aadhaar Number** - Indian Aadhaar ID
- **PAN** - Indian Permanent Account Number
- **NREGA Job Card** - Indian NREGA job card number
- **Voter ID Number** - Indian voter ID
- **IT Fiscal Code** - Italian fiscal code
- And other country-specific identifiers

#### Other Types
- **Age** - Age information
- **VIN** - Vehicle Identification Number
- **License Plate** - License plate numbers
- **Date/Time** - Broader date/time detection (beyond DOB)

### Provider-Specific Capabilities

**Pattern Detector:**
- Fast regex-based detection
- Supports: SSN, EMAIL, PHONE_NUMBER, CREDIT_CARD, IP_ADDRESS, DATE_OF_BIRTH, NAME, BANK_ACCOUNT, IBAN, SWIFT_CODE, AWS_ACCESS_KEY, AWS_SECRET_KEY, ITIN, NATIONAL_INSURANCE_NUMBER, MAC_ADDRESS
- Limited support for: ADDRESS (via field name hints)
- Does not support: PASSPORT, DRIVER_LICENSE, USERNAME, PASSWORD

**Presidio:**
- NLP-based detection with context awareness
- Supports all 20 mapped types (with some variations)
- Can detect 50+ additional entity types including international identifiers
- Best for: Context-aware detection, unstructured text

**AWS Comprehend:**
- Cloud-based ML detection
- Supports all 20 mapped types
- Can detect 36+ entity types including country-specific identifiers
- Best for: AWS ecosystem, international data

**GCP DLP:**
- Cloud-based detection
- Supports all 20 mapped types
- Can detect 100+ info types
- Best for: GCP ecosystem, comprehensive coverage

**Azure Text Analytics:**
- Cloud-based detection
- Supports all 20 mapped types (with some variations)
- Can detect 20+ entity types
- Best for: Azure ecosystem

### Configuration

You can enable/disable specific PII types in your configuration:

```yaml
pii_detection:
  enabled_types:
    # Core types (enabled by default)
    - "SSN"
    - "EMAIL"
    - "PHONE_NUMBER"
    - "ADDRESS"
    - "CREDIT_CARD"
    - "DATE_OF_BIRTH"
    - "PASSPORT"
    - "DRIVER_LICENSE"
    - "IP_ADDRESS"
    - "NAME"
    # Additional types (optional - uncomment to enable)
    # - "BANK_ACCOUNT"
    # - "IBAN"
    # - "SWIFT_CODE"
    # - "AWS_ACCESS_KEY"
    # - "AWS_SECRET_KEY"
    # - "ITIN"
    # - "NATIONAL_INSURANCE_NUMBER"
    # - "USERNAME"
    # - "PASSWORD"
    # - "MAC_ADDRESS"
```

**Note:** The 10 core types are enabled by default. The 10 additional types are available but disabled by default. Uncomment them in your config to enable detection.

---

## PII Provider Selection

### Choose ONE Cloud/LLM Provider

You should choose **ONE provider** (Presidio, AWS, GCP, Azure, or Ollama) and optionally combine it with Pattern for better performance.

### Provider Options

| Provider | Type | Cost | Best For |
|----------|------|------|----------|
| **Pattern** | Regex-based | Free | Fast detection, always recommended |
| **Presidio** | NLP-based | Free | On-premise, high accuracy |
| **AWS Comprehend** | Cloud API | Pay-per-use | AWS ecosystem |
| **GCP DLP** | Cloud API | Pay-per-use | GCP ecosystem |
| **Azure Text Analytics** | Cloud API | Pay-per-use | Azure ecosystem |
| **LLM Agent** | Local LLM (Ollama) | Free | Privacy-first, schema-level analysis (recommended for LLM) |

### Recommended Configurations

**Option 1: Pattern + LLM Agent (Recommended - Default)**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "llm_agent"
  providers_config:
    llm_agent:
      base_url: "http://localhost:11434"
      model: "llama3.2"
```

**Option 2: Pattern + Presidio (NLP-based)**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "presidio"
```
*Requires: `pip install presidio-analyzer spacy && python -m spacy download en_core_web_lg`*

**Option 3: Pattern + AWS**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "aws"
  
  providers_config:
    aws:
      region_name: "us-east-1"
      language_code: "en"
```

**Option 3: Pattern + GCP**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "gcp"
  
  providers_config:
    gcp:
      project_id: "your-project-id"
      location: "global"
```

**Option 4: Pattern + Azure**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "azure"
  
  providers_config:
    azure:
      endpoint: "https://your-resource.cognitiveservices.azure.com/"
      api_key: "your-api-key"
      language: "en"
```

**Option 5: Pattern + LLM Agent (Privacy-First, Recommended for LLM)**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "llm_agent"
  
  providers_config:
    llm_agent:
      base_url: "http://localhost:11434"
      model: "llama3.2"
      timeout: 60
```

### AWS Configuration

**Prerequisites:**
```bash
pip install boto3
```

**Credentials (choose one):**
- IAM Role (recommended for EC2/ECS/Lambda)
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- AWS credentials file: `~/.aws/credentials`

**Configuration:**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "aws"
  
  providers_config:
    aws:
      region_name: "us-east-1"
      language_code: "en"
      # Credentials from IAM role or environment variables
```

### GCP Configuration

**Prerequisites:**
```bash
pip install google-cloud-dlp
```

**Credentials:**
- Service account JSON file
- Default application credentials
- Environment variable: `GOOGLE_APPLICATION_CREDENTIALS`

**Configuration:**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "gcp"
  
  providers_config:
    gcp:
      project_id: "your-project-id"
      location: "global"
      # credentials_path: "/path/to/service-account.json"  # Optional
```

### Azure Configuration

**Prerequisites:**
```bash
pip install azure-ai-textanalytics
```

**Configuration:**
```yaml
pii_detection:
  providers:
    - "pattern"
    - "azure"
  
  providers_config:
    azure:
      endpoint: "https://your-resource.cognitiveservices.azure.com/"
      api_key: "your-api-key"
      language: "en"
```

### LLM Agent Configuration (Recommended for Local LLM)

The `llm_agent` provider uses **schema-level analysis** - the most efficient way to use LLMs for PII detection. It analyzes field names and sample values in a single LLM call per topic.

**Prerequisites:**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama server
ollama serve

# Pull a model (in another terminal)
ollama pull llama3.2
```

**Configuration:**
```yaml
pii_detection:
  providers:
    - "pattern"      # Fast regex-based detection
    - "llm_agent"    # Schema-level LLM analysis
  
  providers_config:
    llm_agent:
      base_url: "http://localhost:11434"
      model: "llama3.2"
      timeout: 60
```

**How Schema-Level Detection Works:**

Instead of checking each field value individually (slow), the LLM agent:
1. Collects all field names from the schema
2. Gathers sample values for context
3. Makes ONE LLM call: "Which of these fields contain PII?"
4. Returns detections for the entire topic

```
┌─────────────────────────────────────────────────────────────┐
│  Schema-Level Analysis (1 LLM call per topic)              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LLM Prompt:                                                │
│  "Analyze these fields for PII:                            │
│   - driver_name: ['John Doe', 'Jane Smith']                │
│   - driver_id: [12345, 67890]                              │
│   - fare_amount: [25.00, 30.50]                            │
│   Which contain PII?"                                       │
│                                                             │
│  LLM Response:                                              │
│  [{"field": "driver_name", "type": "NAME", "conf": 0.95}]  │
│                                                             │
│  Result: 1 LLM call for entire topic!                      │
└─────────────────────────────────────────────────────────────┘
```

**Performance Comparison:**

| Approach | LLM Calls | Time (60 samples × 6 fields) |
|----------|-----------|------------------------------|
| Per-field | 360 calls | ~6 minutes |
| **Schema-level** | **1 call** | **~4 seconds** |

**Recommended Models:**
| Model | Speed | Quality | GPU Required |
|-------|-------|---------|--------------|
| `llama3.2` | Fast | Excellent | Optional |
| `mistral` | Medium | Very Good | Optional |
| `gemma2` | Medium | Good | Optional |
| `llama3.2:1b` | Very Fast | Good | No |

**Benefits:**
- **Privacy**: Data never leaves your environment
- **Cost**: Free after initial setup (no API costs)
- **Efficiency**: 100x fewer LLM calls than per-field approach
- **Intelligence**: LLM understands context from field names

**How Pattern + LLM Agent Work Together:**
- **Pattern detector**: Catches obvious PII (emails, credit cards, SSNs via regex)
- **LLM agent**: Catches context-aware PII (names, addresses based on field names)

---

## Performance Optimization

### Quick Wins

**1. Increase Parallel Workers:**
```yaml
parallel_workers: 20  # Default: 10
max_parallel_partitions: 30  # Default: 20
```

**2. Enable Skip-Based Sampling:**
```yaml
sampling:
  use_skip_based_sampling: true  # 10-20x faster
  early_termination: true  # 30-50% faster
```

**3. Optimize Kafka Consumer:**
```yaml
kafka:
  fetch_min_bytes: 1024
  fetch_max_wait_ms: 100
```

**4. Increase Sample Analysis Workers:**
Already optimized to 20 workers (increased from 10).

### Expected Performance Improvements

| Optimization | Speedup | Impact |
|-------------|---------|--------|
| Skip-based sampling | 10-20x | Very High |
| Early termination | 30-50% | Medium |
| Increased parallel workers | 2x | High |
| Kafka fetch tuning | 20-30% | Medium |

### Performance Configuration

```yaml
# High-performance configuration
parallel_workers: 20
max_parallel_partitions: 30

sampling:
  strategy: "percentage"
  sample_percentage: 5
  use_skip_based_sampling: true
  early_termination: true
  max_partitions_per_topic: 10  # Stop after finding samples in 10 partitions

kafka:
  fetch_min_bytes: 1024
  fetch_max_wait_ms: 100
```

**Partition Limit (`max_partitions_per_topic`):**
- **Purpose**: Limit scanning to a subset of partitions for faster processing
- **Behavior**: Stops after finding samples in X partitions (not just scanning X partitions)
- **Example**: If set to 10, and topic has 50 partitions:
  - Scans partitions in parallel
  - Stops as soon as samples are found in 10 partitions
  - Cancels remaining partition scans
  - **Result**: Faster processing for topics with many partitions
- **Use Case**: Topics with 100+ partitions where sampling from 10-20 partitions is sufficient

---

## Run Modes

### Mode 1: Batch Classification (Default)

**When to use:**
- One-time analysis
- Scheduled jobs (cron)
- Manual execution
- CI/CD pipelines

**Usage:**
```bash
pii-classifier -c config/config.yaml --all-topics
```

**Characteristics:**
- Runs once and exits
- Resource-efficient
- Easy to schedule
- Simple to debug

### Mode 2: API Server

**When to use:**
- Integration with external systems (webhooks, other services)
- Event-driven architectures
- Microservices that need to trigger classification
- On-demand classification

**Usage:**
```bash
pii-classifier -c config/config.yaml --api-server --api-host 0.0.0.0 --api-port 8000
```

**API Endpoints:**
- `GET /health` - Health check
- `POST /api/v1/classify` - Trigger classification

**Example Request:**
```bash
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"topic": "my-topic", "enable_tagging": false}'
```

### Mode 3: Continuous Monitoring

**When to use:**
- Periodic re-analysis
- Ongoing monitoring
- Automated re-classification
- Scheduled periodic analysis

**Usage:**
```bash
pii-classifier -c config/config.yaml --monitor --monitor-interval 3600
```

**Characteristics:**
- Runs continuously
- Re-analyzes topics periodically
- Configurable interval
- Can be stopped with Ctrl+C

### Mode 4: Streaming Mode (Real-Time)

**Purpose:** Process messages as they arrive in real-time.

**When to Use:**
- Real-time PII monitoring
- Continuous schema tagging
- Alert on new PII detections
- Process new records immediately

**Features:**
- ✅ Real-time processing (~100ms latency)
- ✅ Offset tracking (resume from last position)
- ✅ Graceful shutdown (Ctrl+C)
- ✅ Optional schema tagging
- ✅ Low resource usage (single-threaded)

**Usage:**
```bash
# Basic streaming (new messages only)
pii-classifier -c config/config.yaml --streaming

# Stream with schema tagging
pii-classifier -c config/config.yaml --streaming --enable-tagging

# Resume from saved offsets
pii-classifier \
  -c config/config.yaml \
  --streaming \
  --offset-storage ./streaming_offsets.json

# Process all messages from beginning
pii-classifier \
  -c config/config.yaml \
  --streaming \
  --offset-reset earliest
```

**Configuration:**
```yaml
streaming:
  enabled: false  # Enable via --streaming flag
  offset_reset: "latest"  # "latest" (new messages) or "earliest" (all messages)
  offset_storage_path: "./streaming_offsets.json"  # Optional: Path to store offsets
  commit_interval: 100  # Commit offsets every N messages
  poll_timeout: 1.0  # Polling timeout in seconds
```

**How It Works:**
1. Subscribes to Kafka topics
2. Continuously polls for new messages
3. Processes each message immediately:
   - Deserializes (Avro/Protobuf/JSON)
   - Detects PII in all fields
   - Logs detections
   - Tags schema (if enabled)
4. Tracks offsets
5. Commits periodically
6. Saves offsets to file (if configured)

**Performance:**
- **Throughput**: Limited by processing speed (~10-100 messages/sec depending on PII detector)
- **Latency**: ~100ms per message (with Pattern detector)
- **Resource Usage**: Low (single-threaded)

**Comparison with Batch Mode:**

| Feature | Streaming Mode | Batch Mode |
|---------|---------------|------------|
| Latency | Real-time (~100ms) | Minutes to hours |
| Throughput | Limited (single-threaded) | High (parallel) |
| Use Case | Real-time monitoring | Initial assessment |
| Offset Tracking | ✅ Yes | ❌ No |
| Schema Tagging | ✅ Real-time (optional) | ✅ After analysis |
| Resource Usage | Low | High |

---

## API Server

### Starting the API Server

```bash
pii-classifier -c config/config.yaml --api-server
```

### API Endpoints

**Health Check:**
```bash
curl http://localhost:8000/health
```

**Classify Topic:**
```bash
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "my-topic",
    "enable_tagging": false,
    "priority": "normal"
  }'
```

**Request Body:**
```json
{
  "topic": "topic-name",  // Single topic
  "topics": ["topic1", "topic2"],  // Multiple topics
  "enable_tagging": false,  // Whether to tag schemas
  "priority": "normal"  // "normal" or "high"
}
```

**Response:**
```json
{
  "success": true,
  "priority": "normal",
  "topics_analyzed": 1,
  "total_fields_classified": 10,
  "total_pii_fields": 3,
  "errors": [],
  "results": [...],
  "timestamp": "2025-11-09T12:00:00"
}
```

### Integration Example

**External Integration Example:**
```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/classify",
    json={
        "topic": "user-events",
        "enable_tagging": False,
        "priority": "high"
    }
)
result = response.json()
```

---

## Troubleshooting

### Common Issues

**1. "No module named 'presidio_analyzer'"**
```bash
pip install presidio-analyzer
python -m spacy download en_core_web_lg
```

**2. "Failed to connect to Kafka"**
- Check `bootstrap_servers` in config
- Verify network connectivity
- Check credentials (if using SASL)

**3. "Schema Registry connection failed"**
- Verify `url` in config
- Check API key/secret (if required)
- Test connection: `curl http://localhost:8081/subjects`

**4. "No PII detectors available"**
- Check provider configuration
- Verify dependencies installed
- Check provider-specific requirements

**5. "AWS credentials not found"**
- Set environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- Or use IAM role (if on AWS infrastructure)
- Or configure AWS CLI: `aws configure`

**6. "Ollama not available" or "LLM Agent not working"**
- Ensure Ollama is running: `ollama serve`
- Check if model is pulled: `ollama list`
- Pull the model: `ollama pull llama3.2`
- Verify API: `curl http://localhost:11434/api/tags`
- Check logs for "Schema-level detection" messages

**7. Performance Issues**
- Enable skip-based sampling
- Increase parallel workers
- Reduce sample percentage
- Check network latency (for cloud providers)

### Debug Mode

Run with debug logging:
```bash
pii-classifier -c config/config.yaml --all-topics --log-level DEBUG
```

### Verification Steps

**1. Test Kafka Connection:**
```python
from confluent_kafka import Consumer
consumer = Consumer({'bootstrap.servers': 'localhost:9092', 'group.id': 'test'})
topics = consumer.list_topics(timeout=10)
print(f"Connected! Found {len(topics.topics)} topics")
```

**2. Test Schema Registry:**
```bash
curl http://localhost:8081/subjects
```

**3. Test PII Detection:**
```python
from src.config.config_loader import load_config
from src.pii.detector import PIIDetector
from pathlib import Path

config = load_config(Path('config/config.yaml'))
detector = PIIDetector(config['pii_detection'])
result = detector.detect_in_field('email', 'test@example.com')
print(f"Detections: {result}")
```

---

## Additional Resources

- **README.md** - Project overview and quick start guide
- **config/config.yaml.example** - Complete configuration template
- **src/integration/README.md** - REST API integration guide

---

**Last Updated:** November 2025
