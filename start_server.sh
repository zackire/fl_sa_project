#!/bin/bash

echo "======================================"
echo "   FL Aggregator Server Interface     "
echo "======================================"
echo ""

# --- 1. Expected Clients (K) ---
echo "GUIDE: Enter the total number of Edge Clients (K) that will be participating in this session."
read -p "Enter Expected Clients (Press Enter to default to 3): " input_k
input_k=${input_k:-3}
echo ""

# --- 2. Threshold (T) ---
echo "GUIDE: Enter the minimum threshold of clients (T) required to securely reconstruct the global model."
echo "       This number MUST be less than or equal to K."
read -p "Enter Threshold (Press Enter to default to 2): " input_t
input_t=${input_t:-2}
echo ""

# --- 3. Crypto Stack ---
echo "GUIDE: Choose the encryption level:"
echo "       A - X25519 + ChaCha20 + Ascon128"
echo "       B - X25519 + SIMON + Ascon128"
echo "       C - X25519 + PRESENT + ChaChaPoly"
echo "       N - No-Stack (Standard FL Baseline)"
read -p "Enter Crypto Stack [A/B/C/N]: " input_stack
if [ -z "$input_stack" ]; then
    echo "Error: Crypto Stack cannot be empty."
    exit 1
fi

if [ "$input_stack" == "N" ] || [ "$input_stack" == "n" ]; then
    export PROTOCOL_MODE="baseline"
    input_stack="A" 
else
    export PROTOCOL_MODE="secagg"
fi

PC_UPLOAD_IP="100.119.63.85"

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

# Export variables for Docker Compose
export EXPECTED_K=$input_k
export THRESHOLD_T=$input_t
export CRYPTO_STACK=$input_stack
export PROTOCOL_MODE=$PROTOCOL_MODE

echo "🔓 Pre-emptively granting Docker read-access to SSL certificates..."
sudo chmod -R a+rx certs/

# Optional Quality of Life: Add user to Docker group if not already present
if command -v docker >/dev/null 2>&1 && ! groups | grep -q "\bdocker\b"; then
    echo "🔧 First time setup: Adding $USER to the 'docker' group for future convenience..."
    sudo usermod -aG docker $USER || true
fi

if docker info >/dev/null 2>&1; then
    touch .run_start_marker
    # --force-recreate guarantees the container is completely destroyed and rebuilt.
    # This ensures the process starts from scratch and doesn't remember previous rounds.
    echo "🐳 Running Docker Compose natively..."
    docker compose -f docker-compose.server.yml up -d --build --force-recreate
else
    touch .run_start_marker
    # --force-recreate guarantees the container is completely destroyed and rebuilt.
    # This ensures the process starts from scratch and doesn't remember previous rounds.
    echo "🐳 Sudo required for Docker. Escalating privileges..."
    sudo -E docker compose -f docker-compose.server.yml up -d --build --force-recreate
fi

if [ "$(uname -s)" == "Darwin" ]; then
    echo "💻 Running on a MacBook. Skipping file auto-upload."
    if docker info >/dev/null 2>&1; then
        docker logs -f "fl_server"
    else
        sudo docker logs -f "fl_server"
    fi
    exit 0
fi

echo "⏳ Setting up background task to handle uploads..."

# Background subshell
(
    trap '' SIGINT # Prevents Ctrl+C from killing this background task

    if docker info >/dev/null 2>&1; then
        docker wait "fl_server" >/dev/null 2>&1
    else
        sudo docker wait "fl_server" >/dev/null 2>&1
    fi

    echo -e "\n\n📦 Aggregator stopped! Extracting the latest metrics and logs..."
    FILES_TO_ZIP=""

    LATEST_LOG=$(ls -t logs/*.log 2>/dev/null | head -n 1)
    [ ! -z "$LATEST_LOG" ] && FILES_TO_ZIP="$FILES_TO_ZIP $LATEST_LOG"

    LATEST_UTILITY=$(ls -t metrics/results/utilities/*.csv 2>/dev/null | head -n 1)
    [ ! -z "$LATEST_UTILITY" ] && FILES_TO_ZIP="$FILES_TO_ZIP $LATEST_UTILITY"

    if [ ! -z "$FILES_TO_ZIP" ]; then
        tar -czf "results_server.tar.gz" $FILES_TO_ZIP
        echo "📤 Uploading to PC ($PC_UPLOAD_IP)..."
        curl -s -T "results_server.tar.gz" "http://$PC_UPLOAD_IP:8000/results_server.tar.gz"
        echo "✅ Auto-upload complete for server!"
    fi
) &
UPLOADER_PID=$! # Save the process ID of the background task

# Define what happens when you press Ctrl+C
cleanup() {
    echo -e "\n🛑 Ctrl+C detected! Stopping container 'fl_server'..."
    if docker info >/dev/null 2>&1; then
        docker stop "fl_server" >/dev/null
    else
        sudo docker stop "fl_server" >/dev/null
    fi
    echo "⏳ Waiting for auto-upload to finish..."
    wait $UPLOADER_PID
    echo "👋 Done! Exiting."
    exit 0
}

# Trap Ctrl+C (SIGINT) and route it to the cleanup function
trap cleanup SIGINT

echo "💡 Switching to live logs now..."
echo "   (Note: Press Ctrl+C at any time to STOP the server and upload results.)"
echo "=========================================================================="

# Follow logs in the foreground
if docker info >/dev/null 2>&1; then
    docker logs -f "fl_server"
else
    sudo docker logs -f "fl_server"
fi

# If the container finishes naturally on its own (without Ctrl+C)
echo -e "\n⏳ Server finished naturally. Waiting for upload..."
wait $UPLOADER_PID