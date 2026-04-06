import paho.mqtt.client as mqtt
import logging

class MQTTClientHandler:
    def __init__(self, client_id: str, broker_ip: str, port: int = 1883):
        self.client_id = client_id
        self.broker_ip = broker_ip
        self.port = port
        
        # Initialize Paho MQTT Client
        self.client = mqtt.Client(client_id=self.client_id)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        
        # The link to Layer 3 (The SecAgg Orchestrator)
        self.orchestrator = None 

    def set_orchestrator(self, orchestrator):
        """Injects the logic orchestrator into the network listener."""
        self.orchestrator = orchestrator

    def _on_connect(self, client, userdata, flags, rc):
        """Triggered automatically when connected to the Mosquitto broker."""
        if rc == 0:
            logging.info(f"[{self.client_id}] Successfully connected to Mosquitto at {self.broker_ip}")
            
            # Subscribe to the new custom topic structure!
            # Listens to Server Broadcasts across all epochs and rounds
            self.client.subscribe("ci_fl/+/+/server/broadcast")
            
            # Listens to personal messages routed to this specific client
            self.client.subscribe(f"ci_fl/+/+/{self.client_id}/tx")
        else:
            logging.error(f"[{self.client_id}] Connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        """Triggered automatically when a message arrives on a subscribed topic."""
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        # Pass the message up to the Orchestrator
        if self.orchestrator:
            self.orchestrator.process_mqtt_message(topic, payload)
        else:
            logging.warning(f"[{self.client_id}] Message received but no orchestrator attached!")

    def publish(self, topic: str, payload: str):
        """Called by the Orchestrator to send data outward."""
        self.client.publish(topic, payload)

    def start(self):
        """Connects to the broker and starts the asynchronous listening loop."""
        self.client.connect(self.broker_ip, self.port, keepalive=60)
        self.client.loop_start()  # Runs asynchronously in the background
        
    def stop(self):
        """Safely shuts down the network connection."""
        self.client.loop_stop()
        self.client.disconnect()