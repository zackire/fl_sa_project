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

    # ---------------------------------------------------------------------- #
    #  MQTT interface                                                         #
    # ---------------------------------------------------------------------- #

    def _check_in_with_server(self):
        logging.info(f"[{self.client_id}] Checking in with Aggregator Server...")
        payload = json.dumps({
            "meta": {"client_id": self.client_id, "msg_type": "checkin"}
        })
        self.mqtt.publish(f"fl/client/{self.client_id}/to_server", payload)

    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        msg_type = meta.get("msg_type")

        if msg_type == "global_model":
            self._handle_global_model(data)
        elif msg_type == "ignition":
            logging.info(f"\n[{self.client_id}] IGNITION RECEIVED — Starting Round 1...")
            self._send_weights()

    # ---------------------------------------------------------------------- #
    #  Handlers                                                               #
    # ---------------------------------------------------------------------- #

    def _handle_global_model(self, data: dict):
        global_weights_list = data.get("global_weights", [])

        if global_weights_list:
            global_weights = [np.array(w) for w in global_weights_list]
            logging.info(f"\n[{self.client_id}] ====== RECEIVED GLOBAL MODEL ======")
            self._log_weights("Received global weights", global_weights)
            self.model.set_weights(global_weights)

        # In vanilla baseline: no local training, send current weights directly
        self._send_weights()

    # ---------------------------------------------------------------------- #
    #  Sending                                                                #
    # ---------------------------------------------------------------------- #

    def _send_weights(self):
        weights = self.model.get_weights()

        logging.info(f"\n[{self.client_id}] ====== SENDING WEIGHTS TO SERVER ======")
        self._log_weights("Outgoing weights (identical to initialised values)", weights)

        weights_list = [w.tolist() for w in weights]
        payload = json.dumps({
            "meta": {"client_id": self.client_id, "msg_type": "raw_weights"},
            "data": {"weights": weights_list}
        })
        self.mqtt.publish(f"fl/client/{self.client_id}/to_server", payload)
        logging.info(f"[{self.client_id}] Weights published ✓")

    # ---------------------------------------------------------------------- #
    #  Helpers                                                                #
    # ---------------------------------------------------------------------- #

    def _log_weights(self, label: str, weights: list):
        component_labels = ["coef", "intercept"]
        logging.info(f"[{self.client_id}] {label}:")
        for i, w in enumerate(weights):
            lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(
                f"  [{lbl}] shape={w.shape} | values={np.round(w, 6)} | "
                f"sum={np.sum(w):.6f} | L2={np.linalg.norm(w):.6f}"
            )