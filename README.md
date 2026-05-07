# Federated Learning with Secure Aggregation (FL-SA)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
<!-- [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX) -->

A modular testbed for **Federated Learning (FL)** enhanced with **Secure Aggregation (SA)**, enabling privacy-preserving model training across distributed edge and IoT devices. Raw data remains local while model updates are securely masked during aggregation.

> **Status:** Research code accompanying the paper *"Lightweight Cryptography for Secure Aggregation in Federated Learning for Network Anomaly Detection in Critical Infrastructures"* (!!!!!under review / published in [venue], 2026). See [Citation](#citation).

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

> **Prerequisites:** Docker, Docker Compose, and Python 3.10+ on the host. TLS certificates are generated automatically via `generate_certs.sh` on first run.

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

---

## Configuration

| Variable      | Description                        |
| ------------- | ---------------------------------- |
| PROTOCOL_MODE | `secagg` or `baseline`             |
| CRYPTO_STACK  | A / B / C                          |
| EXPECTED_K    | Total number of clients            |
| THRESHOLD_T   | Minimum clients for reconstruction |
| CLIENT_ID     | Unique client identifier           |
| SERVER_IP     | MQTT broker address                |

---

## Project Structure

```text
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

---

## Security Highlights

- Raw data never leaves client devices
- Individual model updates remain private
- Secure aggregation prevents server-side data exposure
- Supports client dropout recovery
- End-to-end encrypted communication via mTLS and AEAD

---

## Reproducing the Experiments

To reproduce the results reported in the paper:

1. Clone this repository at the tagged release used in the paper (see [Releases](https://github.com/zackire/fl_sa_project/releases)).
2. Follow the [Quick Start](#quick-start) instructions to launch the server and clients.
3. Configure `PROTOCOL_MODE` and `CRYPTO_STACK` according to the experiment under study.
4. Per-round metrics are written to `metrics/results/` and can be aggregated for analysis.

---

## Purpose

This project is designed for research and experimentation in:

- Privacy-preserving machine learning
- Lightweight cryptography
- Federated learning systems
- Edge and IoT environments

---

## Citation

If you use this software in your research, please cite it as:

```bibtex
@software{fl_sa_project_2026,
  author       = {Zakire Cukur},
  title        = {{FL-SA: A Modular Testbed for Federated
                   Learning with Secure Aggregation}},
  year         = {2026},
  publisher    = {Zenodo},
  version      = {v1.0.0},
  doi          = {10.5281/zenodo.XXXXXXX},
  url          = {https://github.com/zackire/fl_sa_project}
}
```

<!--
After your first Zenodo release:
  1. Replace XXXXXXX above with your actual DOI suffix.
  2. Replace the author alias with your real name.
  3. Uncomment the DOI badge at the top of this README.
-->

A `CITATION.cff` file is included so GitHub's "Cite this repository" button generates the citation automatically.

---

## License

This project is released under the [MIT License](LICENSE). You are free to use, modify, and distribute it for academic and commercial purposes, provided the copyright notice is preserved.

---

## Acknowledgments

This work was developed as part of research on privacy-preserving federated learning for resource-constrained environments.