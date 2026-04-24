import json
import logging
import threading
import numpy as np

# Machine Learning Logic (Reusing your exact existing files!)
from fl_core.fedavg_logic import aggregate
from communication.payload_builder import PayloadBuilder

class VanillaFLServer:
    def __init__(self, mqtt_handler, expected_k: int):
        self.mqtt = mqtt_handler
        self.expected_k = expected_k
        
        # Simple baseline state
        self.received_weights = {}
        self.current_global_weights = []
        
    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        
        # Fallback to topic extraction if client_id isn't in meta
        client_id = meta.get("client_id", topic.split('/')[-2])
        msg_type = meta.get("msg_type")
        
        # In Vanilla FL, we only care about receiving raw weights
        if msg_type == "raw_weights":
            self._handle_incoming_weights(client_id, data)
            
    def _handle_incoming_weights(self, client_id: str, data: dict):
        if "weights" not in data:
            return
            
        # Convert received standard lists back to NumPy arrays
        client_weights = [np.array(w) for w in data["weights"]]
        self.received_weights[client_id] = client_weights
        
        # Log Incoming weights math
        incoming_sum = sum(np.sum(w) for w in client_weights)
        incoming_l2 = sum(np.linalg.norm(w) for w in client_weights)
        logging.info(f"[Vanilla Server] INCOMING Math Summary from {client_id}: Total Weight Sum: {incoming_sum:.6f} | L2 Norm: {incoming_l2:.6f}")
        logging.info(f"[Vanilla Server] Received raw weights from {client_id}. ({len(self.received_weights)}/{self.expected_k})")
        
        # When all clients have reported in, aggregate!
        if len(self.received_weights) == self.expected_k:
            self._aggregate_and_update()
            
    def _aggregate_and_update(self):
        logging.info("[Vanilla Server] Quorum reached. Executing standard FedAvg...")
        
        all_client_weights = list(self.received_weights.values())
        
        # 1. Sum all the raw client weights together
        summed_weights = []
        num_layers = len(all_client_weights[0])
        for i in range(num_layers):
            layer_sum = sum(client[i] for client in all_client_weights)
            summed_weights.append(layer_sum)
            
        # 2. Pass the sum to your existing FedAvg logic (which divides by K)
        self.current_global_weights = aggregate(summed_weights, self.expected_k)
        logging.info("[Vanilla Server] Global model successfully updated.")
        
        # Final mathematical checks
        final_total_sum = sum(np.sum(w) for w in self.current_global_weights)
        final_total_l2 = sum(np.linalg.norm(w) for w in self.current_global_weights)
        logging.info("================================================================")
        logging.info(f"[Vanilla Server] FINAL TOTAL SUM OF ROUND WEIGHTS: {final_total_sum:.6f}")
        logging.info(f"[Vanilla Server] FINAL L2 NORM OF ROUND WEIGHTS: {final_total_l2:.6f}")
        logging.info("================================================================")
        
        # 3. Trigger the terminal prompt for the next round
        self._prompt_next_round()
        
    def _prompt_next_round(self):
        # Wipe memory for the next round
        self.received_weights.clear() 
        
        def auto_next_round():
            import time
            logging.info("[Vanilla Server] Waiting 20 seconds before starting next round...")
            time.sleep(20)
            logging.info("[Vanilla Server] Broadcasting new global model...")
            
            outgoing_sum = sum(np.sum(w) for w in self.current_global_weights)
            outgoing_l2 = sum(np.linalg.norm(w) for w in self.current_global_weights)
            logging.info(f"[Vanilla Server] OUTGOING Math Summary to Clients -> Total Weight Sum: {outgoing_sum:.6f} | L2 Norm: {outgoing_l2:.6f}")
            
            # Convert NumPy arrays to lists so they can be JSON serialized
            weights_to_send = [w.tolist() for w in self.current_global_weights]
            
            payload = json.dumps({
                "meta": {"msg_type": "global_model"},
                "data": {"global_weights": weights_to_send}
            })
            topic = PayloadBuilder.get_server_broadcast_topic()
            self.mqtt.publish(topic, payload)
                
        # Start the question in a background thread so MQTT doesn't freeze
        threading.Thread(target=auto_next_round, daemon=True).start()