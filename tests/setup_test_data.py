#!/usr/bin/env python3
"""
Create test topics with schemas and produce test data for PII classifier testing.

Topics created:
1. user-profiles       - Full PII: names, emails, SSNs, phones, addresses
2. payment-transactions - Financial PII: credit cards, names, amounts
3. sensor-readings     - No PII: temperature, humidity, device IDs
4. app-metrics         - No PII: counters, gauges, timestamps
5. order-events        - Mixed: order IDs (no PII) + customer names/emails (PII)
6. employee-records    - Heavy PII: SSN, DOB, salary, address
7. empty-topic         - No messages (empty)
"""

import json
import random
import time
import uuid
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic
import requests

KAFKA_BOOTSTRAP = "localhost:19092"
SCHEMA_REGISTRY_URL = "http://localhost:18081"

# ---- Fake data generators ----

FIRST_NAMES = ["John", "Jane", "Alice", "Bob", "Charlie", "Diana", "Edward", "Fiona", "George", "Hannah"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Taylor"]
STREETS = ["123 Main St", "456 Oak Ave", "789 Pine Rd", "321 Elm Dr", "654 Maple Ln"]
CITIES = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"]
STATES = ["NY", "CA", "IL", "TX", "AZ"]

def fake_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def fake_email(name):
    domain = random.choice(["gmail.com", "yahoo.com", "example.com", "company.org"])
    return f"{name.lower().replace(' ', '.')}@{domain}"

def fake_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def fake_phone():
    return f"({random.randint(200,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}"

def fake_credit_card():
    # Generate a Luhn-valid Visa-like number (starts with 4, 16 digits)
    digits = [4] + [random.randint(0, 9) for _ in range(14)]
    # Luhn check digit calculation
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:  # double every second digit from right (0-indexed)
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - (total % 10)) % 10
    digits.append(check)
    num = ''.join(str(d) for d in digits)
    return f"{num[:4]}-{num[4:8]}-{num[8:12]}-{num[12:16]}"

def fake_dob():
    year = random.randint(1960, 2000)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"

def fake_address():
    return f"{random.choice(STREETS)}, {random.choice(CITIES)}, {random.choice(STATES)} {random.randint(10000,99999)}"

def fake_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

# ---- Schema registration ----

SCHEMAS = {
    "user-profiles-value": {
        "type": "record",
        "name": "UserProfile",
        "namespace": "com.test",
        "fields": [
            {"name": "user_id", "type": "string"},
            {"name": "full_name", "type": "string"},
            {"name": "email", "type": "string"},
            {"name": "ssn", "type": "string"},
            {"name": "phone_number", "type": "string"},
            {"name": "address", "type": "string"},
            {"name": "date_of_birth", "type": "string"},
            {"name": "ip_address", "type": "string"},
            {"name": "created_at", "type": "string"}
        ]
    },
    "payment-transactions-value": {
        "type": "record",
        "name": "PaymentTransaction",
        "namespace": "com.test",
        "fields": [
            {"name": "transaction_id", "type": "string"},
            {"name": "card_number", "type": "string"},
            {"name": "cardholder_name", "type": "string"},
            {"name": "amount", "type": "double"},
            {"name": "currency", "type": "string"},
            {"name": "merchant", "type": "string"},
            {"name": "timestamp", "type": "string"}
        ]
    },
    "sensor-readings-value": {
        "type": "record",
        "name": "SensorReading",
        "namespace": "com.test",
        "fields": [
            {"name": "sensor_id", "type": "string"},
            {"name": "temperature", "type": "double"},
            {"name": "humidity", "type": "double"},
            {"name": "pressure", "type": "double"},
            {"name": "location_code", "type": "string"},
            {"name": "reading_time", "type": "string"}
        ]
    },
    "app-metrics-value": {
        "type": "record",
        "name": "AppMetric",
        "namespace": "com.test",
        "fields": [
            {"name": "metric_name", "type": "string"},
            {"name": "value", "type": "double"},
            {"name": "unit", "type": "string"},
            {"name": "host", "type": "string"},
            {"name": "tags", "type": "string"},
            {"name": "timestamp", "type": "long"}
        ]
    },
    "order-events-value": {
        "type": "record",
        "name": "OrderEvent",
        "namespace": "com.test",
        "fields": [
            {"name": "order_id", "type": "string"},
            {"name": "customer_name", "type": "string"},
            {"name": "customer_email", "type": "string"},
            {"name": "product_id", "type": "string"},
            {"name": "quantity", "type": "int"},
            {"name": "total_price", "type": "double"},
            {"name": "status", "type": "string"},
            {"name": "shipping_address", "type": "string"}
        ]
    },
    "employee-records-value": {
        "type": "record",
        "name": "EmployeeRecord",
        "namespace": "com.test",
        "fields": [
            {"name": "employee_id", "type": "string"},
            {"name": "first_name", "type": "string"},
            {"name": "last_name", "type": "string"},
            {"name": "email", "type": "string"},
            {"name": "ssn", "type": "string"},
            {"name": "date_of_birth", "type": "string"},
            {"name": "phone", "type": "string"},
            {"name": "home_address", "type": "string"},
            {"name": "salary", "type": "double"},
            {"name": "department", "type": "string"}
        ]
    }
}


def register_schemas():
    """Register Avro schemas in Schema Registry."""
    print("Registering schemas...")
    for subject, schema in SCHEMAS.items():
        payload = {
            "schemaType": "AVRO",
            "schema": json.dumps(schema)
        }
        resp = requests.post(
            f"{SCHEMA_REGISTRY_URL}/subjects/{subject}/versions",
            json=payload,
            headers={"Content-Type": "application/vnd.schemaregistry.v1+json"}
        )
        if resp.status_code == 200:
            print(f"  Registered {subject} -> id={resp.json()['id']}")
        else:
            print(f"  ERROR registering {subject}: {resp.status_code} {resp.text}")


def create_topics():
    """Create Kafka topics."""
    print("Creating topics...")
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})

    topic_names = list(SCHEMAS.keys())
    topic_names = [t.replace("-value", "") for t in topic_names]
    topic_names.append("empty-topic")

    new_topics = [NewTopic(t, num_partitions=3, replication_factor=1) for t in topic_names]
    results = admin.create_topics(new_topics)
    for topic, future in results.items():
        try:
            future.result()
            print(f"  Created topic: {topic}")
        except Exception as e:
            if "already exists" in str(e):
                print(f"  Topic exists: {topic}")
            else:
                print(f"  ERROR creating {topic}: {e}")


def produce_messages():
    """Produce test messages to all topics."""
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP})

    def delivery_callback(err, msg):
        if err:
            print(f"  Delivery failed: {err}")

    # 1. user-profiles (heavy PII)
    print("\nProducing user-profiles (50 messages, heavy PII)...")
    for i in range(50):
        name = fake_name()
        msg = {
            "user_id": str(uuid.uuid4()),
            "full_name": name,
            "email": fake_email(name),
            "ssn": fake_ssn(),
            "phone_number": fake_phone(),
            "address": fake_address(),
            "date_of_birth": fake_dob(),
            "ip_address": fake_ip(),
            "created_at": "2025-01-15T10:30:00Z"
        }
        producer.produce("user-profiles", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 2. payment-transactions (financial PII)
    print("Producing payment-transactions (40 messages, financial PII)...")
    for i in range(40):
        name = fake_name()
        msg = {
            "transaction_id": f"TXN-{uuid.uuid4().hex[:8].upper()}",
            "card_number": fake_credit_card(),
            "cardholder_name": name,
            "amount": round(random.uniform(5.0, 500.0), 2),
            "currency": random.choice(["USD", "EUR", "GBP"]),
            "merchant": random.choice(["Amazon", "Walmart", "Target", "Best Buy", "Costco"]),
            "timestamp": "2025-01-15T14:22:00Z"
        }
        producer.produce("payment-transactions", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 3. sensor-readings (no PII)
    print("Producing sensor-readings (60 messages, NO PII)...")
    for i in range(60):
        msg = {
            "sensor_id": f"SENSOR-{random.randint(1, 20):03d}",
            "temperature": round(random.uniform(15.0, 35.0), 2),
            "humidity": round(random.uniform(30.0, 80.0), 2),
            "pressure": round(random.uniform(990.0, 1030.0), 2),
            "location_code": f"ZONE-{random.choice(['A', 'B', 'C', 'D'])}{random.randint(1,5)}",
            "reading_time": "2025-01-15T12:00:00Z"
        }
        producer.produce("sensor-readings", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 4. app-metrics (no PII)
    print("Producing app-metrics (45 messages, NO PII)...")
    metrics = ["cpu_usage", "memory_used", "disk_io", "network_in", "network_out", "request_count", "error_rate"]
    for i in range(45):
        msg = {
            "metric_name": random.choice(metrics),
            "value": round(random.uniform(0, 100), 2),
            "unit": random.choice(["percent", "bytes", "count", "ms"]),
            "host": f"web-{random.randint(1, 10):02d}.internal",
            "tags": f"env=prod,region={random.choice(['us-east', 'us-west', 'eu-west'])}",
            "timestamp": int(time.time() * 1000)
        }
        producer.produce("app-metrics", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 5. order-events (mixed - PII in customer fields, not in order fields)
    print("Producing order-events (35 messages, MIXED PII)...")
    for i in range(35):
        name = fake_name()
        msg = {
            "order_id": f"ORD-{random.randint(100000, 999999)}",
            "customer_name": name,
            "customer_email": fake_email(name),
            "product_id": f"PROD-{random.randint(1000, 9999)}",
            "quantity": random.randint(1, 5),
            "total_price": round(random.uniform(10.0, 300.0), 2),
            "status": random.choice(["pending", "confirmed", "shipped", "delivered"]),
            "shipping_address": fake_address()
        }
        producer.produce("order-events", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 6. employee-records (heavy PII + salary)
    print("Producing employee-records (30 messages, HEAVY PII)...")
    departments = ["Engineering", "Marketing", "Sales", "Finance", "HR", "Legal"]
    for i in range(30):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        msg = {
            "employee_id": f"EMP-{random.randint(10000, 99999)}",
            "first_name": first,
            "last_name": last,
            "email": f"{first.lower()}.{last.lower()}@company.com",
            "ssn": fake_ssn(),
            "date_of_birth": fake_dob(),
            "phone": fake_phone(),
            "home_address": fake_address(),
            "salary": round(random.uniform(50000, 200000), 2),
            "department": random.choice(departments)
        }
        producer.produce("employee-records", json.dumps(msg).encode(), callback=delivery_callback)
    producer.flush()
    print("  Done.")

    # 7. empty-topic - no messages
    print("Topic 'empty-topic' left empty intentionally.")

    print(f"\nAll test data produced successfully!")
    print(f"Total messages: 260 across 6 topics (+ 1 empty topic)")


def verify_setup():
    """Verify everything is set up correctly."""
    print("\n" + "="*60)
    print("VERIFICATION")
    print("="*60)

    # Check schemas
    resp = requests.get(f"{SCHEMA_REGISTRY_URL}/subjects")
    subjects = resp.json()
    print(f"\nSchema Registry subjects ({len(subjects)}):")
    for s in sorted(subjects):
        print(f"  - {s}")

    # Check topics
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})
    metadata = admin.list_topics(timeout=10)
    user_topics = [t for t in metadata.topics if not t.startswith("_")]
    print(f"\nKafka topics ({len(user_topics)}):")
    for t in sorted(user_topics):
        partitions = len(metadata.topics[t].partitions)
        print(f"  - {t} ({partitions} partitions)")


if __name__ == "__main__":
    print("="*60)
    print("Setting up test data for PII Classification Agent")
    print("="*60)
    print(f"Kafka: {KAFKA_BOOTSTRAP}")
    print(f"Schema Registry: {SCHEMA_REGISTRY_URL}")
    print()

    create_topics()
    register_schemas()
    produce_messages()
    verify_setup()

    print("\n" + "="*60)
    print("Setup complete! Ready to test pii-classifier.")
    print("="*60)
