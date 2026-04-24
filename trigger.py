import paho.mqtt.client as mqtt
import json
import os

def check_and_generate_certs():
    client_id = "admin_trigger"
    base_dir = f"certs/clients/{client_id}"
    
    if not os.path.exists(base_dir):
        print(f"[!] TLS Certificates for '{client_id}' not found. Generating now...")
        os.system(f"./generate_certs.sh {client_id}")
    
    return f"{base_dir}/ca.crt", f"{base_dir}/client.crt", f"{base_dir}/client.key"

def ignite():
    ca_cert, client_cert, client_key = check_and_generate_certs()
    
    cl = mqtt.Client(client_id="admin_trigger")
    cl.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key)
    cl.connect("localhost", 8883)
    
    # Broadcast to all clients to initiate Round 0
    topic = "fl/server/broadcast"
    payload = json.dumps({
        "meta": {
            "epoch": 1,
            "round": 0,
            "msg_type": "ignition",
            "client_id": "admin_trigger"
        },
        "data": {}
    })
    
    cl.publish(topic, payload, qos=2)
    cl.disconnect()
    print(f"Ignition command deployed to {topic}. FL cascade starting...")

if __name__ == '__main__':
    ignite()
