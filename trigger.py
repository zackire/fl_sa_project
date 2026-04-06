import paho.mqtt.client as mqtt
import json

def ignite():
    cl = mqtt.Client(client_id="FL_Admin_Trigger")
    cl.connect("localhost", 1883)
    
    # Broadcast to all clients to initiate Round 0
    # The clients' `ci_fl/+/+/server/broadcast` subscription will catch this
    topic = "ci_fl/epoch_1/round_0/server/broadcast"
    payload = json.dumps({"command": "ignite_fl"})
    
    cl.publish(topic, payload)
    cl.disconnect()
    print(f"Ignition command deployed to {topic}. FL cascade starting...")

if __name__ == '__main__':
    ignite()
