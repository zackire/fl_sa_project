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
echo "       A - Base Cryptography & AEAD (Heavy)"
echo "       B - Simon/Speck Lightweight PRG (Medium)"
echo "       C - Present Lightweight PRG (Fastest)"
read -p "Enter Crypto Stack [A/B/C] (Press Enter to default to A): " input_stack
input_stack=${input_stack:-A}

echo ""
echo "🚀 Starting Client container '$input_client_id' connecting to '$input_server_ip'..."

# Pass the variables inline and run compose
CLIENT_ID=$input_client_id \
SERVER_IP=$input_server_ip \
CRYPTO_STACK=$input_stack \
docker-compose -f docker-compose.client.yml up -d --build

echo "Done! Run 'docker logs -f fl_$input_client_id' to watch the network traffic."
