"""Setup script for PII Classification Agent."""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Read version from __version__.py
version_file = Path(__file__).parent / "src" / "__version__.py"
version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file.read_text(), re.M)
version = version_match.group(1) if version_match else "1.0.0"

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="pii-classifier",
    version=version,
    description="Automatically detect and classify PII in Kafka topics",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pii-classifier=src.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
    ],
)
