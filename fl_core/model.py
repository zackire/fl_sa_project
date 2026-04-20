import numpy as np
import logging
from typing import List

class MockSecAggModel:
    """
    A lightweight mock model designed to test the dimensional translation 
    and cryptographic masking of the Secure Aggregation engine.
    """
    def __init__(self, num_features: int = 10, hidden_dim: int = 5):
        self.num_features = num_features
        self.hidden_dim = hidden_dim
        # Generates a mock weight matrix and bias vector
        self.weights = [
            np.random.uniform(-0.5, 0.5, (self.num_features, self.hidden_dim)), 
            np.random.uniform(-0.5, 0.5, (self.hidden_dim,)) 
        ]

    def get_weights(self) -> List[np.ndarray]:
        return self.weights

    def set_weights(self, global_weights: List[np.ndarray]):
        if global_weights and len(global_weights) > 0:
            self.weights = global_weights
            logging.info("Model weights updated with new global weights.")

    def fit(self):
        """
        MOCK TRAINING: Simulates learning by shifting the multidimensional 
        arrays slightly using random Gaussian noise.
        """
        logging.info("Simulating local training epoch...")
        noise_w = np.random.normal(0, 0.05, (self.num_features, self.hidden_dim))
        noise_b = np.random.normal(0, 0.05, (self.hidden_dim,))
        
        self.weights = [
            self.weights[0] + noise_w,
            self.weights[1] + noise_b
        ]