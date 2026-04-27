import paho.mqtt.client as mqtt
import logging
from communication.payload_builder import PayloadBuilder

class MQTTClientHandler:
    def __init__(self, client_id: str, broker_ip: str, port: int = 8883, ca_path: str = None, cert_path: str = None, key_path: str = None):
        self.client_id = client_id
        self.broker_ip = broker_ip
        self.port = port
        
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.client_id)
        
        # Configure mTLS if certificates are provided (port usually 8883 for TLS)
        if ca_path and cert_path and key_path:
            self.client.tls_set(ca_certs=ca_path, certfile=cert_path, keyfile=key_path)
            self.client.tls_insecure_set(True)
            
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe
        
        self.orchestrator = None 

    def set_orchestrator(self, orchestrator):
        self.orchestrator = orchestrator

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            logging.info(f"[{self.client_id}] Successfully connected to Mosquitto at {self.broker_ip}")
            # Use PayloadBuilder for dynamic routing rules with QoS 2
            self.client.subscribe(PayloadBuilder.get_server_broadcast_topic(), qos=2)
            self.client.subscribe(PayloadBuilder.get_client_inbox_topic(self.client_id), qos=2)
        else:
            logging.error(f"[{self.client_id}] Connection failed with code {reason_code}")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        logging.warning(f"[{self.client_id}] Disconnected from broker (rc={reason_code})")

    def _on_publish(self, client, userdata, mid, reason_code=None, properties=None):
        logging.debug(f"[{self.client_id}] QoS 2 Message successfully delivered (mid={mid})")

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        logging.info(f"[{self.client_id}] Subscribed to topic successfully (mid={mid})")

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        if self.orchestrator:
            self.orchestrator.process_mqtt_message(topic, payload)
        else:
            logging.warning(f"[{self.client_id}] Message received but no orchestrator attached!")

    def publish(self, topic: str, payload: str):
        # Enforce QoS 2 for all transmissions
        self.client.publish(topic, payload, qos=2)

    def start(self):
        self.client.connect(self.broker_ip, self.port, keepalive=60)
        self.client.loop_start() 
        
    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()