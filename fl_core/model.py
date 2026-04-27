import numpy as np
import logging
from typing import List


# ---------------------------------------------------------------------------
# Fixed weight registry — one explicit array per client.
# These never change. What you see here is exactly what the server receives.
# coef      : shape (10,)  — one weight per feature
# intercept : shape (1,)
# ---------------------------------------------------------------------------
CLIENT_WEIGHTS = {
    "client1": {
        "coef":      np.array([ 0.10,  0.20,  0.30,  0.40,  0.50,  0.60,  0.70,  0.80,  0.90,  1.00]),
        "intercept": np.array([ 0.05]),
    },
    "client2": {
        "coef":      np.array([-0.10,  0.00,  0.10,  0.20,  0.30,  0.40,  0.50,  0.60,  0.70,  0.80]),
        "intercept": np.array([ 0.00]),
    },
    "client3": {
        "coef":      np.array([-0.50, -0.40, -0.30, -0.20, -0.10,  0.00,  0.10,  0.20,  0.30,  0.40]),
        "intercept": np.array([-0.05]),
    },
}

# Expected FedAvg result (manual verification):
#   coef      = [-0.1667, -0.0667,  0.0333,  0.1333,  0.2333,
#                 0.3333,  0.4333,  0.5333,  0.6333,  0.7333]
#   intercept = 0.0000


class MockSecAggModel:
    """
    Mock Logistic Regression model for Federated Learning experiments.

    Weight layout (mirrors sklearn LogisticRegression):
        weights[0]  ->  coef       shape: (num_features,)  i.e. (10,)
        weights[1]  ->  intercept  shape: (1,)

    Weights are hardcoded per client_id. No randomness, no linspace,
    no fit() transformation — what is initialised is exactly what gets sent.
    """

    def __init__(self, client_id: str = "client1", num_features: int = 10):
        self.client_id = client_id

        if client_id not in CLIENT_WEIGHTS:
            raise ValueError(
                f"Unknown client_id '{client_id}'. "
                f"Expected one of: {list(CLIENT_WEIGHTS.keys())}"
            )

        profile   = CLIENT_WEIGHTS[client_id]
        coef      = profile["coef"].copy()
        intercept = profile["intercept"].copy()

        self.weights: List[np.ndarray] = [coef, intercept]

        logging.info(f"[{self.client_id}] Model initialised (NO fit() applied)")
        logging.info(f"[{self.client_id}]   coef      shape={coef.shape} | values={coef}")
        logging.info(f"[{self.client_id}]   intercept shape={intercept.shape} | values={intercept}")

    def get_weights(self) -> List[np.ndarray]:
        return self.weights

    def set_weights(self, global_weights: List[np.ndarray]):
        """Replace local weights with the received global averages."""
        if global_weights and len(global_weights) > 0:
            self.weights = [w.copy() for w in global_weights]
            logging.info(f"[{self.client_id}] Weights updated from global model:")
            logging.info(f"[{self.client_id}]   coef      = {np.round(self.weights[0], 6)}")
            logging.info(f"[{self.client_id}]   intercept = {np.round(self.weights[1], 6)}")

    def fit(self):
        """
        NOT USED in the vanilla baseline.
        No-op placeholder — keeps the interface compatible with future
        SecAgg experiments that will add real local training.
        """
        logging.info(
            f"[{self.client_id}] fit() called — no-op in vanilla baseline. "
            "Weights unchanged."
        )