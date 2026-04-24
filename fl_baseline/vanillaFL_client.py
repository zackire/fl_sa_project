import json
import logging
import numpy as np

# Reusing your existing communication utilities
from communication.payload_builder import PayloadBuilder

class VanillaFLClient:
    def __init__(self, client_id: str, mqtt_handler, local_model):
        self.client_id = client_id
        self.mqtt = mqtt_handler
        self.model = local_model

    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        
        msg_type = meta.get("msg_type")
        
        # In Vanilla FL, the client only acts when the server sends the global model (or an ignition signal)
        if msg_type == "global_model":
            self._handle_global_model(data)
        elif msg_type == "ignition":
            self._simulate_training_and_send()

    def _handle_global_model(self, data: dict):
        global_weights_list = data.get("global_weights", [])
        
        if global_weights_list:
            logging.info(f"[{self.client_id}] Received global model. Updating local weights...")
            # Convert standard lists back to NumPy arrays for your model
            global_weights = [np.array(w) for w in global_weights_list]
            self.model.set_weights(global_weights)
        else:
            logging.info(f"[{self.client_id}] Received empty global model. Starting fresh...")
            
        self._simulate_training_and_send()
        
    def _simulate_training_and_send(self):
        logging.info(f"[{self.client_id}] Simulating local training epoch...")
        
        # 1. Train the model (hooks right into your existing mock Logistic Regression)
        self.model.fit()
        
        # 2. Extract the newly trained weights
        updated_weights = self.model.get_weights()
        
        # 3. Dispatch the raw weights to the server
        self._send_raw_weights(updated_weights)
        
    def _send_raw_weights(self, weights: list):
        # Calculate raw mathematical weight values to log
        total_weight_sum = sum(np.sum(w) for w in weights)
        l2_norm_sum = sum(np.linalg.norm(w) for w in weights)
        logging.info(f"[{self.client_id}] Math Summary -> Total Weight Sum: {total_weight_sum:.6f} | Combined L2 Norm: {l2_norm_sum:.6f}")

        # Convert NumPy arrays to lists so they can be securely JSON formatted
        weights_list = [w.tolist() for w in weights]
        
        payload = json.dumps({
            "meta": {
                "client_id": self.client_id,
                "msg_type": "raw_weights"
            },
            "data": {
                "weights": weights_list
            }
        })
        
        # You can use PayloadBuilder here if you have a specific uplink topic method, 
        # otherwise we manually construct the topic it sends back to the server:
        topic = f"fl/client/{self.client_id}/to_server" 
        self.mqtt.publish(topic, payload)
        logging.info(f"[{self.client_id}] Raw weights dispatched to server.")