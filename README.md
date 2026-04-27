# Federated Learning with Secure Aggregation (FL-SA)

A modular testbed for **Federated Learning (FL)** enhanced with **Secure Aggregation (SA)**, enabling privacy-preserving model training across distributed edge devices. Raw data remains local while model updates are securely masked during aggregation.

---

## Overview

This project provides two execution modes:

- **Secure Aggregation (`secagg`)**  
  Privacy-preserving federated learning using masking, secret sharing, and dropout recovery.

- **Baseline (`baseline`)**  
  Standard federated learning without cryptographic protection, used for performance comparison.

### Key Features

- Pluggable **cryptographic stacks** (A / B / C)
- **MQTT-based communication** with mTLS security
- **Dockerized deployment** for reproducibility
- Per-round **performance metrics** (latency, CPU, RAM, bandwidth)
- Modular and extensible architecture for experimentation

---

## Technology Stack

- **Language:** Python 3.10+
- **Containerization:** Docker, Docker Compose
- **Communication:** Eclipse Mosquitto (MQTT)
- **Security:** mTLS (X.509 certificates)
- **Libraries:** NumPy, scikit-learn, cryptography, pycryptodome

---

## System Architecture

- **Server:** Coordinates training rounds and performs aggregation  
- **Clients:** Train locally and send masked model updates  
- **MQTT Broker:** Handles communication between nodes  

The system supports both distributed deployment (e.g., edge devices) and local execution via Docker.

---

## Workflow

1. Server initializes and broadcasts the global model  
2. Clients train locally on private data  
3. Clients apply masking (in `secagg` mode)  
4. Masked updates are sent to the server  
5. Server aggregates updates without accessing individual values  
6. Updated global model is redistributed  

Secure Aggregation ensures that only the **final aggregated result** is revealed.

---
## Quick Start

**Start Server** 
```bash
./start_server.sh
```

**Start Clients**
```bash
./start_client.sh
```

**Trigger Training**
```bash
python trigger.py
```

**Monitor Logs and Metrics**
```bash
docker logs -f fl_server
ls metrics/results/
```

## Configuration
| Variable      | Description                        |
| ------------- | ---------------------------------- |
| PROTOCOL_MODE | `secagg` or `baseline`             |
| CRYPTO_STACK  | A / B / C                          |
| EXPECTED_K    | Total number of clients            |
| THRESHOLD_T   | Minimum clients for reconstruction |
| CLIENT_ID     | Unique client identifier           |
| SERVER_IP     | MQTT broker address                |


## Project Structure
```bash
main_server.py        # Server entry point
main_client.py        # Client entry point
trigger.py            # Training trigger script

communication/        # MQTT and logging modules
crypto/               # Cryptographic stacks
secure_aggregation/   # Secure aggregation protocol
fl_baseline/          # Baseline FL implementation
fl_core/              # Model and aggregation logic
metrics/              # Performance tracking
```

## Security Highlights
- Raw data never leaves client devices
- Individual model updates remain private
- Secure aggregation prevents server-side data exposure
- Supports client dropout recovery
- End-to-end encrypted communication via mTLS and AEAD

## Purpose

This project is designed for research and experimentation in:

- Privacy-preserving machine learning
- Lightweight cryptography
- Federated learning systems
- Edge and IoT environments

## License

This project is intended for academic and research purposes.