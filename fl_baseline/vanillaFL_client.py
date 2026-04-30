import json
import logging
import numpy as np


class VanillaFLClient:
    def __init__(self, client_id: str, mqtt_handler, local_model, metrics=None):
        self.client_id = client_id
        self.mqtt = mqtt_handler
        self.model = local_model
        self.metrics = metrics
        self.current_round = 1

        self._check_in_with_server()

    # ---------------------------------------------------------------------- #
    #  MQTT interface                                                         #
    # ---------------------------------------------------------------------- #

    def _publish(self, topic: str, payload: str):
        if self.metrics:
            self.metrics.record_bytes(len(payload.encode("utf-8")))
        self.mqtt.publish(topic, payload)

    # ---------------------------------------------------------------------- #
    #  MQTT interface                                                         #
    # ---------------------------------------------------------------------- #

    def _check_in_with_server(self):
        logging.info(f"[{self.client_id}] Checking in with server...")
        payload = json.dumps({
            "meta": {"client_id": self.client_id, "msg_type": "checkin"}
        })
        self._publish(f"fl/client/{self.client_id}/to_server", payload)

    def process_mqtt_message(self, topic: str, payload: str):
        if self.metrics:
            self.metrics.record_recv_bytes(len(payload.encode("utf-8")))
            
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})
        msg_type = meta.get("msg_type")

        if msg_type == "global_model":
            self.current_round += 1
            if self.metrics:
                self.metrics.round_start(self.current_round)
            self._handle_global_model(data)
        elif msg_type == "ignition":
            round_num = meta.get("round", 1)
            self.current_round = round_num
            if self.metrics:
                self.metrics.round_start(self.current_round)
            logging.info(f"[{self.client_id}] Ignition received — starting Round {round_num}.")
            # Send the PREVIOUSLY trained weights (trained on boot)
            self._send_weights()

    # ---------------------------------------------------------------------- #
    #  Handlers                                                               #
    # ---------------------------------------------------------------------- #

    def _handle_global_model(self, data: dict):
        # 1. Send the ALREADY computed local weights from the previous round
        self._send_weights()  # Note: _send_weights calls metrics.round_end()!

        # 2. Post-round processing: Apply new global weights and Train
        global_weights_list = data.get("global_weights", [])

        if global_weights_list:
            global_weights = [np.array(w) for w in global_weights_list]
            logging.info(f"[{self.client_id}] Global model received from server.")
            _log_weights(self.client_id, global_weights, label="Global model")
            self.model.set_weights(global_weights)

        # Train locally outside the measurement window
        logging.info(f"[{self.client_id}] Running post-round local training …")
        self.model.fit()

    # ---------------------------------------------------------------------- #
    #  Sending                                                                #
    # ---------------------------------------------------------------------- #

    def _send_weights(self):
        weights = self.model.get_weights()
        _log_weights(self.client_id, weights, label="Sending weights to server")

        weights_list = [w.tolist() for w in weights]
        payload = json.dumps({
            "meta": {"client_id": self.client_id, "msg_type": "raw_weights"},
            "data": {"weights": weights_list}
        })
        self._publish(f"fl/client/{self.client_id}/to_server", payload)
        logging.info(f"[{self.client_id}] Weights published to server ✓")
        
        if self.metrics:
            self.metrics.round_end(self.current_round)


# ---------------------------------------------------------------------- #
#  Shared logging helper                                                  #
# ---------------------------------------------------------------------- #

def _log_weights(client_id: str, weights: list, label: str = "Weights"):
    component_labels = ["coef", "intercept"]
    logging.info(f"[{client_id}] {label}:")
    for i, w in enumerate(weights):
        lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
        logging.info(f"  [{lbl}]  {np.round(w, 6)}")