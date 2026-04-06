import numpy as np
from sklearn.linear_model import SGDClassifier

class AnomalyDetectionLR:
    """Logistic Regression model optimized for anomaly detection on edge nodes."""
    
    def __init__(self):
        # We use log_loss to maintain a probabilistic classifier natively.
        self.model = SGDClassifier(
            loss="log_loss",
            penalty="l2",
            max_iter=1,  # In FL, we typically run 1 epoch per round over the data, handled organically
            warm_start=True,
            random_state=42
        )
        self.is_initialized = False

    def get_weights(self) -> list[np.ndarray]:
        """Retrieve the current weights and intercept from the model."""
        if not self.is_initialized:
            # Provide dummy weights if model hasn't been fit yet
            # In a real use case, input feature size needs to be known/initialized
            return []
            
        return [self.model.coef_, self.model.intercept_]

    def set_weights(self, weights: list[np.ndarray]):
        """Set the weights and intercept into the model."""
        if not weights:
            return
            
        self.model.coef_ = weights[0]
        self.model.intercept_ = weights[1]
        
        # If classes are not initialized yet
        if not self.is_initialized:
            self.model.classes_ = np.array([0, 1])  # Binary classification assumed
            self.is_initialized = True

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 1):
        """Train the model locally."""
        if not self.is_initialized:
            self.model.classes_ = np.array([0, 1])
            self.is_initialized = True
            
        for _ in range(epochs):
            self.model.partial_fit(X, y, classes=np.array([0, 1]))

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> float:
        """Evaluate the model on a test set and return accuracy."""
        if not self.is_initialized:
            return 0.0
        return self.model.score(X, y)
import numpy as np
import logging

class AnomalyDetectionLR:
    """
    A mock Logistic Regression model to test the Secure Aggregation network pipes.
    Generates random weight arrays instead of doing actual ML training.
    """
    def __init__(self, num_features: int = 10):
        self.num_features = num_features
        # Simulate weights (array of features) and bias (array of 1)
        self.weights = [
            np.random.uniform(-0.5, 0.5, self.num_features),
            np.random.uniform(-0.5, 0.5, 1)
        ]

    def set_weights(self, global_weights: list):
        """Receives the new global model from the server."""
        if global_weights and len(global_weights) > 0:
            self.weights = global_weights
            logging.info("Model weights updated with new global weights.")

    def get_weights(self) -> list:
        """Returns the current weights for masking and transmission."""
        return self.weights

    def fit(self, X_train, y_train):
        """
        MOCK TRAINING: Simulates learning by shifting the weights slightly 
        using random Gaussian noise.
        """
        logging.info("Simulating local training on mock data...")
        
        noise_w = np.random.normal(0, 0.05, self.num_features)
        noise_b = np.random.normal(0, 0.05, 1)
        
        self.weights = [
            self.weights[0] + noise_w,
            self.weights[1] + noise_b
        ]
        logging.info("Mock training complete. Delta weights generated.")