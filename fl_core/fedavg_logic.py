from typing import List
import numpy as np
import logging


def aggregate(summed_weights: List[np.ndarray], num_survivors: int) -> List[np.ndarray]:
    """
    Compute the average of the securely aggregated model parameters.
    Since the Crypto Stack outputs a strict mathematical sum of all weights, 
    we find the average by dividing by the active participant count.
    """
    if not summed_weights or num_survivors <= 0:
        return []
        
    logging.info(f"Computing FedAvg over {num_survivors} cryptographically summed client weights.")
    
    # Divide the unmasked numpy array sum by the number of clients
    averaged_weights = [
        layer_sum / num_survivors for layer_sum in summed_weights
    ]
    
    return averaged_weights