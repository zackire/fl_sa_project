import numpy as np
import logging

def load_local_data(client_id: str, num_samples: int = 100, num_features: int = 10):
    """
    Generates dummy network traffic data to test the FL orchestrators.
    Returns: X_train (features), y_train (labels 0 or 1)
    """
    logging.info(f"Loading mock dataset for {client_id} (Samples: {num_samples})")
    
    # Generate random floats for features (e.g., packet sizes, connection durations)
    X_train = np.random.rand(num_samples, num_features)
    
    # Generate random 0 or 1 for labels (e.g., Normal vs. Anomaly)
    y_train = np.random.randint(0, 2, num_samples)
    
    return X_train, y_train