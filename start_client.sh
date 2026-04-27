#!/bin/bash

echo "======================================"
echo "   FL Edge Client Startup Interface   "
echo "======================================"
echo ""

# --- 1. Client ID ---
echo "GUIDE: Enter a simple, unique name without spaces for this device."
read -p "Enter a unique Client ID (e.g. client_1, factory_pi, edge_node): " input_client_id
if [ -z "$input_client_id" ]; then
    echo "Error: Client ID cannot be empty."
    exit 1
fi
echo ""

# --- 2. Server IP ---
echo "GUIDE: Enter the local network IPv4 address where the Aggregator Server is running."
read -p "Enter the Server's IP address (e.g. 192.168.1.100 or 10.0.0.5): " input_server_ip
if [ -z "$input_server_ip" ]; then
    echo "Error: Server IP cannot be empty."
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

# Logic to set PROTOCOL_MODE based on selection
if [ "$input_stack" == "N" ] || [ "$input_stack" == "n" ]; then
    export PROTOCOL_MODE="baseline"
    input_stack="A"
else
    export PROTOCOL_MODE="secagg"
fi

echo "🔒 Checking for existing mTLS certificates for '$input_client_id'..."
if [ ! -d "certs/clients/$input_client_id" ]; then
    echo "   [!] Certificates not found. Auto-provisioning via secure OpenSSL..."
    ./generate_certs.sh "$input_client_id"
else
    echo "   [+] Certificates found securely."
fi

echo ""
echo "🚀 Starting Client container '$input_client_id' connecting to '$input_server_ip'..."

sudo CLIENT_ID=$input_client_id \
SERVER_IP=$input_server_ip \
CRYPTO_STACK=$input_stack \
PROTOCOL_MODE=$PROTOCOL_MODE \
docker compose -p "project_$input_client_id" -f docker-compose.client.yml up -d --build

echo "Done! Run 'docker logs -f fl_$input_client_id' to watch the network traffic."