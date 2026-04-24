#!/bin/bash

# Directory Setup
SERVER_DIR="certs/server"
CLIENT_DIR="certs/clients"
CA_KEY="$SERVER_DIR/ca.key"
CA_CERT="$SERVER_DIR/ca.crt"

mkdir -p "$SERVER_DIR"
mkdir -p "$CLIENT_DIR"

echo "========================================="
echo "   MQTT OpenSSL mTLS Generator Utility   "
echo "========================================="

# --- 1. Root Certificate Authority (CA) ---
if [ ! -f "$CA_CERT" ]; then
    echo "[!] Root CA not found. Generating a new Root CA..."
    
    # Generate CA Private Key
    openssl genpkey -algorithm RSA -out "$CA_KEY" -pkeyopt rsa_keygen_bits:2048
    
    # Generate CA Certificate (valid for 10 years)
    openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CERT" -subj "/C=US/ST=State/L=City/O=FL_Organization/CN=FL_Root_CA"
    
    echo "[+] Root CA Generated successfully!"
else
    echo "[+] Root CA already exists."
fi

# --- 2. Broker Server Certificate (If missing) ---
if [ ! -f "$SERVER_DIR/server.crt" ]; then
    echo "[!] Broker Server Certificate missing. Generating..."
    openssl genpkey -algorithm RSA -out "$SERVER_DIR/server.key" -pkeyopt rsa_keygen_bits:2048
    openssl req -new -key "$SERVER_DIR/server.key" -out "$SERVER_DIR/server.csr" -subj "/C=US/ST=State/L=City/O=FL_Organization/CN=mqtt-broker"
    
    # Sign with CA (Valid for 10 years)
    openssl x509 -req -in "$SERVER_DIR/server.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_DIR/server.crt" -days 3650
    rm "$SERVER_DIR/server.csr"
    echo "[+] Server Certificate Generated successfully!"
fi

# --- 3. Optional Client Certificate Generation ---
CLIENT_ID=$1
if [ -n "$CLIENT_ID" ]; then
    echo "[!] Generating Client Certificate for ID: $CLIENT_ID"
    TARGET_DIR="$CLIENT_DIR/$CLIENT_ID"
    
    if [ -f "$TARGET_DIR/client.crt" ]; then
        echo "[+] Certificates already exist for $CLIENT_ID. Skipping."
        exit 0
    fi
    
    mkdir -p "$TARGET_DIR"
    
    # Generate Client Key
    openssl genpkey -algorithm RSA -out "$TARGET_DIR/client.key" -pkeyopt rsa_keygen_bits:2048
    
    # Generate Client CSR (CRITICAL: Common Name MUST match the Client ID to pass Mosquitto Identity check)
    openssl req -new -key "$TARGET_DIR/client.key" -out "$TARGET_DIR/client.csr" -subj "/C=US/ST=State/L=City/O=FL_Organization/CN=$CLIENT_ID"
    
    # Sign with CA (Valid for 1 year)
    openssl x509 -req -in "$TARGET_DIR/client.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$TARGET_DIR/client.crt" -days 365
    rm "$TARGET_DIR/client.csr"
    
    # Copy CA cert to the client folder for convenience (Docker volume mounting requires only 1 folder)
    cp "$CA_CERT" "$TARGET_DIR/ca.crt"
    echo "[+] Client Certificate generated inside $TARGET_DIR/"
fi
