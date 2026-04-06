import paho.mqtt.client as mqtt
import logging

class MQTTServerHandler:
    def __init__(self, broker_ip: str, port: int = 1883):
        self.broker_ip = broker_ip
        self.port = port
        
        # Initialize Paho MQTT Client (Server doesn't need a specific client_id)
        self.client = mqtt.Client(client_id="FL_Aggregation_Server")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        
        self.orchestrator = None 

    def set_orchestrator(self, orchestrator):
        self.orchestrator = orchestrator

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"[SERVER] Successfully connected to Mosquitto at {self.broker_ip}")
            # Subscribe to the CI tree format mapped by PayloadBuilder
            self.client.subscribe("ci_fl/+/+/+/tx")
            self.client.subscribe("ci_fl/+/+/+/broadcast")
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
        self.client.publish(topic, payload)

    def start(self):
        self.client.connect(self.broker_ip, self.port, keepalive=60)
        self.client.loop_start() 
        
    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()