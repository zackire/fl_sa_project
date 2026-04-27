import json
import logging
import numpy as np


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
        logging.info(f"[{self.client_id}] Checking in with server...")
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
            round_num = meta.get("round", 1)
            logging.info(f"[{self.client_id}] Ignition received — starting Round {round_num}.")
            self._send_weights()

    # ---------------------------------------------------------------------- #
    #  Handlers                                                               #
    # ---------------------------------------------------------------------- #

    def _handle_global_model(self, data: dict):
        global_weights_list = data.get("global_weights", [])

        if global_weights_list:
            global_weights = [np.array(w) for w in global_weights_list]
            logging.info(f"[{self.client_id}] Global model received from server.")
            _log_weights(self.client_id, global_weights, label="Global model")
            self.model.set_weights(global_weights)

        self._send_weights()

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
        self.mqtt.publish(f"fl/client/{self.client_id}/to_server", payload)
        logging.info(f"[{self.client_id}] Weights published to server ✓")


# ---------------------------------------------------------------------- #
#  Shared logging helper                                                  #
# ---------------------------------------------------------------------- #

def _log_weights(client_id: str, weights: list, label: str = "Weights"):
    component_labels = ["coef", "intercept"]
    logging.info(f"[{client_id}] {label}:")
    for i, w in enumerate(weights):
        lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
        logging.info(f"  [{lbl}]  {np.round(w, 6)}")