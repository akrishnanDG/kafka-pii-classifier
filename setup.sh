#!/bin/bash
# Setup script for PII Classification Agent
# Installs CLI tool and Ollama for LLM-based PII detection

set -e

echo "=========================================="
echo "PII Classification Agent - Setup"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version
echo ""

# Install Python dependencies and CLI tool
echo "Installing Python dependencies..."
pip install -e .
echo ""

# Check if Ollama is installed
echo "Checking Ollama installation..."
if command -v ollama &> /dev/null; then
    echo "✅ Ollama is installed"
else
    echo "Ollama not found. Installing..."
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo ""

# Pull LLM model
echo "Pulling llama3.2 model (this may take a few minutes)..."
ollama pull llama3.2
echo ""

# Verify installation
echo "Verifying installation..."
pii-classifier --version
echo ""

echo "=========================================="
echo "✅ Setup complete!"
echo "=========================================="
echo ""
echo "Start Ollama server (in a separate terminal):"
echo "  ollama serve"
echo ""
echo "Then run the classifier:"
echo "  pii-classifier -c config/config.yaml --all-topics --dry-run"
echo ""
