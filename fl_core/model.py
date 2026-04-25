# import numpy as np
# import logging
# from typing import List

# class MockSecAggModel:
#     """
#     A lightweight mock model designed to test the dimensional translation 
#     and cryptographic masking of the Secure Aggregation engine.
#     """
#     def __init__(self, num_features: int = 10, hidden_dim: int = 5):
#         self.num_features = num_features
#         self.hidden_dim = hidden_dim
#         # Generates a mock weight matrix and bias vector
#         self.weights = [
#             np.random.uniform(-0.5, 0.5, (self.num_features, self.hidden_dim)), 
#             np.random.uniform(-0.5, 0.5, (self.hidden_dim,)) 
#         ]

#     def get_weights(self) -> List[np.ndarray]:
#         return self.weights

#     def set_weights(self, global_weights: List[np.ndarray]):
#         if global_weights and len(global_weights) > 0:
#             self.weights = global_weights
#             logging.info("Model weights updated with new global weights.")

#     def fit(self):
#         """
#         MOCK TRAINING: Simulates learning by shifting the multidimensional 
#         arrays slightly using random Gaussian noise.
#         """
#         logging.info("Simulating local training epoch...")
#         noise_w = np.random.normal(0, 0.05, (self.num_features, self.hidden_dim))
#         noise_b = np.random.normal(0, 0.05, (self.hidden_dim,))
        
#         self.weights = [
#             self.weights[0] + noise_w,
#             self.weights[1] + noise_b
#         ]


import numpy as np
import logging
from typing import List

class MockSecAggModel:
    """
    A strictly deterministic mock model designed for reproducible experimental beds.
    No random functions are used. Weights and training shifts are strictly fixed.
    """
    def __init__(self, client_id: str = "client1", num_features: int = 10, hidden_dim: int = 5):
        self.num_features = num_features
        self.hidden_dim = hidden_dim
        self.client_id = client_id
        
        # DEFINING 3 FIXED, REALISTIC ARRAY SETS -> Using linspace generates a realistic spread of floats without using random()
        
        total_w_elements = self.num_features * self.hidden_dim
        
        if "1" in self.client_id:
            # Client 1: Positive leaning coefficients
            fixed_w = np.linspace(0.01, 0.25, total_w_elements).reshape(self.num_features, self.hidden_dim)
            fixed_b = np.linspace(0.01, 0.05, self.hidden_dim)
            
        elif "2" in self.client_id:
            # Client 2: Balanced coefficients
            fixed_w = np.linspace(-0.15, 0.15, total_w_elements).reshape(self.num_features, self.hidden_dim)
            fixed_b = np.linspace(-0.05, 0.05, self.hidden_dim)
            
        else: 
            # Client 3: Negative leaning coefficients
            fixed_w = np.linspace(-0.25, -0.01, total_w_elements).reshape(self.num_features, self.hidden_dim)
            fixed_b = np.linspace(-0.05, -0.01, self.hidden_dim)

        self.weights = [fixed_w, fixed_b]

    def get_weights(self) -> List[np.ndarray]:
        return self.weights

    def set_weights(self, global_weights: List[np.ndarray]):
        if global_weights and len(global_weights) > 0:
            self.weights = global_weights
            logging.info("Model coefficients updated with new global averages.")

    def fit(self):
        """
        DETERMINISTIC TRAINING: Simulates learning without random noise.
        It mathematically shifts the coefficients so you can still track 
        the L2 Norm changing across multiple rounds.
        """
        logging.info("Simulating deterministic local training epoch...")
        
        # A fixed mathematical gradient step
        # Multiplying by 0.98 acts like 'weight decay', ensuring the L2 norm 
        # predictably converges round after round.
        self.weights = [
            self.weights[0] * 0.98 - 0.005,
            self.weights[1] * 0.98 - 0.005
        ]