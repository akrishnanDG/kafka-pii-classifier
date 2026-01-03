"""PII type definitions and metadata."""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass


class PIIType(Enum):
    """Enumeration of PII types."""
    SSN = "SSN"
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    ADDRESS = "ADDRESS"
    CREDIT_CARD = "CREDIT_CARD"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PASSPORT = "PASSPORT"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    IP_ADDRESS = "IP_ADDRESS"
    NAME = "NAME"
    # Additional PII types
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IBAN = "IBAN"
    SWIFT_CODE = "SWIFT_CODE"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    ITIN = "ITIN"
    NATIONAL_INSURANCE_NUMBER = "NATIONAL_INSURANCE_NUMBER"
    USERNAME = "USERNAME"
    PASSWORD = "PASSWORD"
    MAC_ADDRESS = "MAC_ADDRESS"


@dataclass
class PIIDetection:
    """PII detection result."""
    pii_type: PIIType
    confidence: float
    value: str
    pattern_matched: str
    field_name: Optional[str] = None


# PII type metadata
PII_TYPE_METADATA: Dict[PIIType, Dict[str, Any]] = {
    PIIType.SSN: {
        "name": "Social Security Number",
        "tags": ["PII", "PII-SSN"],
        "risk_level": "high",
    },
    PIIType.EMAIL: {
        "name": "Email Address",
        "tags": ["PII", "PII-Email"],
        "risk_level": "medium",
    },
    PIIType.PHONE_NUMBER: {
        "name": "Phone Number",
        "tags": ["PII", "PII-Phone-Number"],
        "risk_level": "medium",
    },
    PIIType.ADDRESS: {
        "name": "Physical Address",
        "tags": ["PII", "PII-Address"],
        "risk_level": "medium",
    },
    PIIType.CREDIT_CARD: {
        "name": "Credit Card Number",
        "tags": ["PII", "PII-Credit-Card"],
        "risk_level": "high",
    },
    PIIType.DATE_OF_BIRTH: {
        "name": "Date of Birth",
        "tags": ["PII", "PII-Date-Of-Birth"],
        "risk_level": "medium",
    },
    PIIType.PASSPORT: {
        "name": "Passport Number",
        "tags": ["PII", "PII-Passport"],
        "risk_level": "high",
    },
    PIIType.DRIVER_LICENSE: {
        "name": "Driver's License",
        "tags": ["PII", "PII-Driver-License"],
        "risk_level": "high",
    },
    PIIType.IP_ADDRESS: {
        "name": "IP Address",
        "tags": ["PII", "PII-IP-Address"],
        "risk_level": "low",
    },
    PIIType.NAME: {
        "name": "Person Name",
        "tags": ["PII", "PII-Name"],
        "risk_level": "medium",
    },
    PIIType.BANK_ACCOUNT: {
        "name": "Bank Account Number",
        "tags": ["PII", "PII-Bank-Account"],
        "risk_level": "high",
    },
    PIIType.IBAN: {
        "name": "International Bank Account Number",
        "tags": ["PII", "PII-IBAN"],
        "risk_level": "high",
    },
    PIIType.SWIFT_CODE: {
        "name": "SWIFT/BIC Code",
        "tags": ["PII", "PII-SWIFT"],
        "risk_level": "medium",
    },
    PIIType.AWS_ACCESS_KEY: {
        "name": "AWS Access Key",
        "tags": ["PII", "PII-AWS-Access-Key", "SECRET"],
        "risk_level": "high",
    },
    PIIType.AWS_SECRET_KEY: {
        "name": "AWS Secret Key",
        "tags": ["PII", "PII-AWS-Secret-Key", "SECRET"],
        "risk_level": "high",
    },
    PIIType.ITIN: {
        "name": "Individual Tax Identification Number",
        "tags": ["PII", "PII-ITIN"],
        "risk_level": "high",
    },
    PIIType.NATIONAL_INSURANCE_NUMBER: {
        "name": "National Insurance Number",
        "tags": ["PII", "PII-NI-Number"],
        "risk_level": "high",
    },
    PIIType.USERNAME: {
        "name": "Username",
        "tags": ["PII", "PII-Username"],
        "risk_level": "low",
    },
    PIIType.PASSWORD: {
        "name": "Password",
        "tags": ["PII", "PII-Password", "SECRET"],
        "risk_level": "high",
    },
    PIIType.MAC_ADDRESS: {
        "name": "MAC Address",
        "tags": ["PII", "PII-MAC-Address"],
        "risk_level": "low",
    },
}


def get_pii_tags(pii_type: PIIType) -> list:
    """Get tags for a PII type."""
    return PII_TYPE_METADATA[pii_type]["tags"]

