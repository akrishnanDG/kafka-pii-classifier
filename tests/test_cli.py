"""Unit tests for CLI interface."""

import pytest
from click.testing import CliRunner
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import main, BANNER, print_version
from src.__version__ import __version__


class TestCLI:
    """Test CLI commands and options."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_version_flag(self, runner):
        """Test --version flag displays version."""
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert __version__ in result.output
        assert 'pii-classifier' in result.output

    def test_version_short_flag(self, runner):
        """Test -V short flag displays version."""
        result = runner.invoke(main, ['-V'])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help_flag(self, runner):
        """Test --help displays usage information."""
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert '--config' in result.output
        assert '--topics' in result.output
        assert '--streaming' in result.output
        assert '--api-server' in result.output

    def test_help_short_flag(self, runner):
        """Test -h short flag displays help."""
        result = runner.invoke(main, ['-h'])
        assert result.exit_code == 0
        assert 'Usage:' in result.output

    def test_missing_config_file(self, runner):
        """Test error when config file doesn't exist."""
        result = runner.invoke(main, ['--config', '/nonexistent/config.yaml'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output.lower() or 'error' in result.output.lower()

    def test_banner_content(self):
        """Test banner contains expected content."""
        assert 'PII' in BANNER
        assert 'Kafka' in BANNER
        assert 'Detect' in BANNER or 'classify' in BANNER

    def test_all_modes_in_help(self, runner):
        """Test all operation modes are documented in help."""
        result = runner.invoke(main, ['--help'])
        assert 'Batch' in result.output or 'batch' in result.output
        assert 'API' in result.output or 'api' in result.output
        assert 'streaming' in result.output
        assert 'monitor' in result.output or 'continuous' in result.output


class TestCLIOptions:
    """Test CLI option parsing."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_topics_option_multiple(self, runner):
        """Test -t option can be specified multiple times."""
        result = runner.invoke(main, ['-h'])
        # The help text mentions multiple times across wrapped lines
        assert '-t, --topics' in result.output
        assert 'multiple' in result.output.lower()

    def test_log_level_choices(self, runner):
        """Test log level has correct choices."""
        result = runner.invoke(main, ['--help'])
        assert 'DEBUG' in result.output
        assert 'INFO' in result.output
        assert 'WARNING' in result.output
        assert 'ERROR' in result.output

    def test_offset_reset_choices(self, runner):
        """Test offset reset has correct choices."""
        result = runner.invoke(main, ['--help'])
        assert 'latest' in result.output
        assert 'earliest' in result.output


class TestVersion:
    """Test version module."""

    def test_version_format(self):
        """Test version follows semantic versioning."""
        parts = __version__.split('.')
        assert len(parts) >= 2, "Version should have at least major.minor"
        for part in parts:
            assert part.isdigit() or part.replace('-', '').replace('alpha', '').replace('beta', '').replace('rc', '').isdigit()

    def test_version_not_empty(self):
        """Test version is not empty."""
        assert __version__
        assert len(__version__) > 0

