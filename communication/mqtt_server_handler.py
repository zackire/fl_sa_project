import paho.mqtt.client as mqtt
import logging
from communication.payload_builder import PayloadBuilder

class MQTTServerHandler:
    def __init__(self, broker_ip: str, port: int = 8883, ca_path: str = None, cert_path: str = None, key_path: str = None):
        self.broker_ip = broker_ip
        self.port = port
        
        self.client = mqtt.Client(client_id="FL_Aggregation_Server")
        
        if ca_path and cert_path and key_path:
            self.client.tls_set(ca_certs=ca_path, certfile=cert_path, keyfile=key_path)
            
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        
        self.orchestrator = None 

    def set_orchestrator(self, orchestrator):
        self.orchestrator = orchestrator

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"[SERVER] Successfully connected to Mosquitto at {self.broker_ip}")
            # Subscribe to the new wildly decoupled MQTT payload struct mapping
            self.client.subscribe(PayloadBuilder.get_server_broadcast_topic(), qos=2)
            self.client.subscribe("fl/client/+/to_server", qos=2)
        else:
            logging.error(f"[SERVER] Connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        # Prevent the server from processing its own broadcast messages
        if "broadcast" in topic:
            return
            
        if self.orchestrator:
            self.orchestrator.process_mqtt_message(topic, payload)
        else:
            logging.warning("[SERVER] Message received but no orchestrator attached!")

    def publish(self, topic: str, payload: str):
        self.client.publish(topic, payload, qos=2)

    def start(self):
        self.client.connect(self.broker_ip, self.port, keepalive=60)
        self.client.loop_start() 
        
    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()