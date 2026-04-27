#!/bin/bash

echo "======================================"
echo "   FL Aggregator Server Interface     "
echo "======================================"
echo ""

# --- 1. Expected Clients (K) ---
echo "GUIDE: Enter the total number of Edge Clients (K) that will be participating in this session."
read -p "Enter Expected Clients (e.g. 3): " input_k
if [ -z "$input_k" ]; then
    echo "Error: Field cannot be empty."
    exit 1
fi
echo ""

# --- 2. Threshold (T) ---
echo "GUIDE: Enter the minimum threshold of clients (T) required to securely reconstruct the global model."
echo "       This number MUST be less than or equal to K."
read -p "Enter Threshold (e.g. 2): " input_t
if [ -z "$input_t" ]; then
    echo "Error: Field cannot be empty."
    exit 1
fi
echo ""

# --- 3. Crypto Stack ---
echo "GUIDE: Choose the encryption level:"
echo "       A - X25519 + ChaCha20 + Ascon128"
echo "       B - X25519 + SIMON + Ascon128"
echo "       C - X25519 + PRESENT + ChaChaPoly"
echo "       N - No-Stack (Standard FL Baseline)"
read -p "Enter Crypto Stack [A/B/C/N] (Press Enter to default to A): " input_stack
input_stack=${input_stack:-A}

if [ "$input_stack" == "N" ] || [ "$input_stack" == "n" ]; then
    export PROTOCOL_MODE="baseline"
    input_stack="A" 
else
    export PROTOCOL_MODE="secagg"
fi

echo "🔒 Checking for existing mTLS certificates for 'fl_server'..."
if [ ! -d "certs/clients/fl_server" ]; then
    echo "   [!] Certificates not found. Auto-provisioning via secure OpenSSL..."
    ./generate_certs.sh "fl_server"
else
    echo "   [+] Certificates found securely."
fi

echo ""
echo "🌐 Ensuring Docker network 'fl_shared_bridge' exists..."
docker network inspect fl_shared_bridge >/dev/null 2>&1 || docker network create fl_shared_bridge

echo "🚀 Starting Mosquitto Broker and Aggregator Server..."

sudo EXPECTED_K=$input_k \
THRESHOLD_T=$input_t \
CRYPTO_STACK=$input_stack \
PROTOCOL_MODE=$PROTOCOL_MODE \
docker-compose -f docker-compose.server.yml up -d --build

echo "Done! Run 'docker logs -f fl_server' to watch the server orchestrate the training round."