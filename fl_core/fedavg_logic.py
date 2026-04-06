from functools import reduce
from typing import List, Tuple

import numpy as np

def local_fit(model, global_weights, X_train, y_train):
    """Execution stub for orchestrator."""
    if len(global_weights) > 0:
        model.set_weights(global_weights)
    
    # Assuming standard scikit-learn or similar fit mechanics
    model.fit(X_train, y_train)
    return model.get_weights(), len(X_train)

def aggregate(results: List[Tuple[List[np.ndarray], int]]) -> List[np.ndarray]:
    """Compute weighted average of model parameters.
    
    Args:
        results: A list of tuples, where each tuple contains a list of
                 NumPy arrays representing the model parameters (weights),
                 and an integer representing the number of examples.
                 
    Returns:
        A list of NumPy arrays representing the aggregated parameters.
    """
    if not results:
        return []
        
    # Calculate the total number of examples used during training
    num_examples_total = sum(num_examples for (_, num_examples) in results)

    # Create a list of weights, each multiplied by the related number of examples
    weighted_weights = [
        [layer * num_examples for layer in weights] for weights, num_examples in results
    ]

    # Compute average weights of each layer
    weights_prime: List[np.ndarray] = [
        reduce(np.add, layer_updates) / num_examples_total
        for layer_updates in zip(*weighted_weights)
    ]
    
    return weights_prime
