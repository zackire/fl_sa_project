import json
import logging
import threading
import time
import numpy as np
from fl_core.fedavg_logic import aggregate
from communication.payload_builder import PayloadBuilder

class VanillaFLServer:
    def __init__(self, mqtt_handler, expected_k: int):
        self.mqtt = mqtt_handler
        self.expected_k = expected_k
        
        self.active_clients = set()
        self.received_weights = {}
        self.current_global_weights = []
        self.round_number = 1
        
    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        
        client_id = meta.get("client_id", topic.split('/')[-2])
        msg_type = meta.get("msg_type")
        
        if msg_type == "checkin":
            self._handle_checkin(client_id)
        elif msg_type == "raw_weights":
            self._handle_incoming_weights(client_id, data)

    def _handle_checkin(self, client_id: str):
        # Ignore duplicate check-ins
        if client_id in self.active_clients:
            return
            
        self.active_clients.add(client_id)
        logging.info(f"[Server] Client Check-in: {client_id} is ready. ({len(self.active_clients)}/{self.expected_k})")
        
        if len(self.active_clients) == self.expected_k:
            logging.info("[Server] ALL CLIENTS CONNECTED! Starting simulation in 3 seconds...")
            time.sleep(3)
            self._broadcast_ignition()

    def _broadcast_ignition(self):
        logging.info("\n========================================================")
        logging.info(f"                 STARTING ROUND {self.round_number}                 ")
        logging.info("========================================================")
        payload = json.dumps({"meta": {"msg_type": "ignition", "round": 0}, "data": {}})
        self.mqtt.publish("fl/server/broadcast", payload)

    def _handle_incoming_weights(self, client_id: str, data: dict):
        if "weights" not in data: 
            return
            
        client_weights = [np.array(w) for w in data["weights"]]
        self.received_weights[client_id] = client_weights
        
        # Calculate Math Summary for the incoming client's arrays
        w_sum = sum(np.sum(w) for w in client_weights)
        w_l2 = sum(np.linalg.norm(w) for w in client_weights)
        logging.info(f"[Server] Received from {client_id} -> Weight Sum: {w_sum:.4f} | L2 Norm: {w_l2:.4f}")
        
        if len(self.received_weights) == self.expected_k:
            time.sleep(1) # Small pause for readability
            self._aggregate_and_update()
            
    def _aggregate_and_update(self):
        logging.info(f"[Server] Quorum reached! Slicing and computing standard FedAvg...")
        time.sleep(2) # Give you time to read the terminal
        
        all_client_weights = list(self.received_weights.values())
        
        summed_weights = []
        # Logistic Regression typically has 2 components: coefficients and intercept
        num_components = len(all_client_weights[0]) 
        for i in range(num_components):
            component_sum = sum(client[i] for client in all_client_weights)
            summed_weights.append(component_sum)
            
        self.current_global_weights = aggregate(summed_weights, self.expected_k)
        
        final_sum = sum(np.sum(w) for w in self.current_global_weights)
        final_l2 = sum(np.linalg.norm(w) for w in self.current_global_weights)
        
        logging.info("\n========================================================")
        logging.info("                 ROUND RESULTS                       ")
        logging.info("========================================================")
        logging.info(f"[Server] Global Model Updated via FedAvg.")
        logging.info(f"[Server] NEW Global Math -> Total Sum: {final_sum:.4f} | L2 Norm: {final_l2:.4f}")
        logging.info("========================================================\n")
        
        self.round_number += 1
        self._prompt_next_round()
        
    def _prompt_next_round(self):
        self.received_weights.clear() 
        
        def auto_start():
            logging.info("[Server] Reading time... Next epoch begins in 10 seconds.")
            time.sleep(10) 
            
            logging.info("\n========================================================")
            logging.info(f"                 STARTING ROUND {self.round_number}                 ")
            logging.info("========================================================")
            logging.info("[Server] Broadcasting new Global Model to all clients...")
            
            weights_to_send = [w.tolist() for w in self.current_global_weights]
            payload = json.dumps({"meta": {"msg_type": "global_model"}, "data": {"global_weights": weights_to_send}})
            self.mqtt.publish("fl/server/broadcast", payload)
                
        threading.Thread(target=auto_start, daemon=True).start()