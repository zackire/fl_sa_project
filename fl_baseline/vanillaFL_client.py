import json
import logging
import time
import numpy as np
from communication.payload_builder import PayloadBuilder

class VanillaFLClient:
    def __init__(self, client_id: str, mqtt_handler, local_model):
        self.client_id = client_id
        self.mqtt = mqtt_handler
        self.model = local_model
        
        self._check_in_with_server()

    def _check_in_with_server(self):
        logging.info(f"[{self.client_id}] Checking in with Aggregator Server...")
        payload = json.dumps({"meta": {"client_id": self.client_id, "msg_type": "checkin"}})
        topic = f"fl/client/{self.client_id}/to_server"
        self.mqtt.publish(topic, payload)

    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        
        msg_type = meta.get("msg_type")
        
        if msg_type == "global_model":
            self._handle_global_model(data)
        elif msg_type == "ignition":
            logging.info(f"\n[{self.client_id}] IGNITION RECEIVED: Starting Round 1...")
            self._simulate_training_and_send()

    def _handle_global_model(self, data: dict):
        global_weights_list = data.get("global_weights", [])
        
        if global_weights_list:
            logging.info(f"[{self.client_id}] Received New Global Model. Updating local Logistic Regression coefficients...")
            global_weights = [np.array(w) for w in global_weights_list]
            self.model.set_weights(global_weights)
            
        self._simulate_training_and_send()
        
    def _simulate_training_and_send(self):
        logging.info(f"[{self.client_id}] Simulating local training epoch (fitting model)...")
        time.sleep(2) # Pause for terminal readability
        
        self.model.fit()
        updated_weights = self.model.get_weights()
        
        # UI: Print a tiny snippet of the actual coefficient array being sent
        first_array_snippet = updated_weights[0].flatten()[:3] 
        logging.info(f"[{self.client_id}] Sending Raw Weights to Server. Snippet: {first_array_snippet}...")
        
        weights_list = [w.tolist() for w in updated_weights]
        payload = json.dumps({
            "meta": {"client_id": self.client_id, "msg_type": "raw_weights"},
            "data": {"weights": weights_list}
        })
        
        topic = f"fl/client/{self.client_id}/to_server" 
        self.mqtt.publish(topic, payload)