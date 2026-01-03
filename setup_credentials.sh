#!/bin/bash
# Setup script for Kafka and Schema Registry credentials
# This script helps you set environment variables for your API keys

echo "=========================================="
echo "Kafka & Schema Registry Credentials Setup"
echo "=========================================="
echo ""
echo "Please provide your credentials:"
echo ""

# Kafka credentials
read -p "Kafka Bootstrap Servers (e.g., pkc-xxxxx.us-east-1.aws.confluent.cloud:9092): " KAFKA_BOOTSTRAP_SERVERS
read -p "Kafka Security Protocol (SASL_SSL or PLAINTEXT) [default: SASL_SSL]: " KAFKA_SECURITY_PROTOCOL
KAFKA_SECURITY_PROTOCOL=${KAFKA_SECURITY_PROTOCOL:-SASL_SSL}
read -p "Kafka SASL Mechanism (PLAIN, SCRAM-SHA-256, etc.) [default: PLAIN]: " KAFKA_SASL_MECHANISM
KAFKA_SASL_MECHANISM=${KAFKA_SASL_MECHANISM:-PLAIN}
read -p "Kafka API Key: " KAFKA_API_KEY
read -s -p "Kafka API Secret: " KAFKA_API_SECRET
echo ""

# Schema Registry credentials
echo ""
read -p "Schema Registry URL (e.g., https://xxxxx.us-east-1.aws.confluent.cloud): " SCHEMA_REGISTRY_URL
read -p "Schema Registry API Key: " SCHEMA_REGISTRY_API_KEY
read -s -p "Schema Registry API Secret: " SCHEMA_REGISTRY_API_SECRET
echo ""

# Create .env file
ENV_FILE=".env"
cat > "$ENV_FILE" << EOF
# Kafka Configuration
export KAFKA_BOOTSTRAP_SERVERS="$KAFKA_BOOTSTRAP_SERVERS"
export KAFKA_SECURITY_PROTOCOL="$KAFKA_SECURITY_PROTOCOL"
export KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM"
export KAFKA_API_KEY="$KAFKA_API_KEY"
export KAFKA_API_SECRET="$KAFKA_API_SECRET"

# Schema Registry Configuration
export SCHEMA_REGISTRY_URL="$SCHEMA_REGISTRY_URL"
export SCHEMA_REGISTRY_API_KEY="$SCHEMA_REGISTRY_API_KEY"
export SCHEMA_REGISTRY_API_SECRET="$SCHEMA_REGISTRY_API_SECRET"
EOF

echo ""
echo "✅ Credentials saved to .env file"
echo ""
echo "To use these credentials, run:"
echo "  source .env"
echo ""
echo "Or add them to your shell profile (~/.zshrc or ~/.bashrc)"
echo ""

