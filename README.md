# Project Documentation: Federated Learning with Secure Aggregation (FL-SA)

This repository provides a complete framework for implementing **Federated Learning (FL)** enhanced by **Secure Aggregation (SA)** protocols. It is designed to facilitate decentralized machine learning where data privacy is maintained through cryptographic masking and secure multi-party computation.

---

## Project Concept

### What is Federated Learning?
In traditional machine learning, data is collected from various sources and sent to a central server for training. In **Federated Learning**, the process is reversed: the model is sent to the data sources (clients). Each client trains the model locally on their own device and only sends the resulting "model updates" (gradients) back to the central server. This ensures that raw, sensitive data never leaves the client's device.

### What is Secure Aggregation?
While Federated Learning protects raw data, the model updates themselves can sometimes leak information about the underlying dataset. **Secure Aggregation** adds a layer of encryption that allows a central server to calculate the sum of all client updates without ever being able to see any individual update. The server only sees the final combined result, ensuring mathematical proof of privacy.

---

## Testbed Architecture and Hardware Structure

The project is designed to run on a hardware testbed consisting of multiple **Raspberry Pi** nodes. This physical separation mimics a real-world edge computing environment.

* **Central Aggregator (Server Node):** One Raspberry Pi acts as the central hub. It manages the global model state, coordinates the training rounds, and performs the final secure aggregation of incoming updates.
* **Training Nodes (Client Nodes):** Multiple Raspberry Pis act as individual clients. Each node possesses its own local dataset and performs the heavy lifting of training the model locally before masking the weights.
* **Network & Performance Monitor:** A dedicated node is used to monitor the MQTT traffic and network overhead. It ensures the communication between the server and clients remains stable and measures the latency of the Secure Aggregation protocol.
* **MQTT Broker:** The communication backbone (Eclipse Mosquitto) typically resides on the Server Node or a dedicated gateway, facilitating the publish/subscribe messaging model.

---

## Technical Architecture

The system is built on a distributed microservices architecture using the following components:

* **fl_core/**: Contains the machine learning logic, model architectures, and local training procedures.
* **secure_aggregation/**: The core privacy logic, including masking functions and multi-party coordination.
* **communication/**: Logic for the MQTT client/server interface and message routing.
* **crypto/**: Low-level cryptographic utilities for key generation and data encryption.
* **mosquitto/**: Configuration files for the MQTT broker environment.

---

## Deployment Guide

### 1. Environment Preparation
Ensure each Raspberry Pi in the testbed has the following software installed:
* **Python 3.10+**
* **Docker Desktop** (or Docker Engine with Docker Compose for Linux)

### 2. Installation
Clone the repository on all participating nodes:
```bash
git clone https://github.com/zackire/fl_sa_project.git
cd fl_sa_project
pip install -r requirements.txt
```

### 3. Network Infrastructure Setup
Deploy the MQTT broker via Docker on the designated Server or Gateway node:
```bash
docker-compose up -d
```
This command starts the Mosquitto broker in the background, providing the communication bridge for the entire testbed.

### 4. Executing the Training Cycle

**Step A: Initialize the Server Node**
On the Raspberry Pi designated as the server, start the aggregator:
```bash
python main_server.py
```

**Step B: Initialize the Client Nodes**
On each Raspberry Pi acting as a client, run the client script. Ensure the configuration points to the Server Node's IP address:
```bash
python main_client.py
```

**Step C: Start the Network Monitor**
Run the monitoring tools to capture performance metrics and communication logs:
```bash
# Example monitor execution
python monitor.py
```

**Step D: Initiate Training**
Once all nodes are connected and idle, use the trigger script to start the federated learning process:
```bash
python trigger.py
```

---

## Security and Privacy Compliance
This implementation follows the principle of **Privacy by Design**. By combining MQTT-based transport with Secure Aggregation, the system remains resilient against:
1.  **Server Intrusion:** Even if the central server is compromised, individual client updates are mathematically masked and unreadable in isolation.
2.  **Eavesdropping:** Communication is routed through the broker with cryptographic payloads.
3.  **Data Leakage:** Raw data never leaves the Raspberry Pi client nodes; only encrypted gradients are shared.
