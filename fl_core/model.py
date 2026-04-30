import os
import logging
import numpy as np
import pandas as pd
from typing import List, Tuple
from datetime import datetime
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, precision_score, recall_score

# ── Configuration & Partition Map ─────────────────────────────────────────────
CLIENT_PARTITION_MAP = {
    "client1": 0,
    "client2": 1,
    "client3": 2,
}

# Feature engineering constants
FEATURE_COLS = [
    "duration",
    "src_bytes", "dst_bytes",
    "missed_bytes",
    "src_pkts", "dst_pkts",
    "src_ip_bytes", "dst_ip_bytes",
    "src_port", "dst_port",
    "proto",
    "service",
    "conn_state",
]

LOG_SCALE_COLS = [
    "duration",
    "src_bytes", "dst_bytes",
    "missed_bytes",
    "src_pkts", "dst_pkts",
    "src_ip_bytes", "dst_ip_bytes",
    "src_port", "dst_port",
]

CATEGORICAL_COLS = ["proto", "service", "conn_state"]
LABEL_COL = "label"

GLOBAL_CATEGORIES = {
    "proto": ['tcp', 'udp', 'icmp', 'unknown'],
    "service": ['-', 'dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp', 'dhcp', 'irc', 'unknown'],
    "conn_state": [
        'OTH', 'REJ', 'S1', 'RSTR', 'SF', 'RSTO',
        'SH', 'S3', 'S0', 'SHR', 'S2', 'RSTOS0', 'RSTRH', 'unknown'
    ],
}

# ── Dataset Resolution ────────────────────────────────────────────────────────

_KAGGLE_SLUG        = "arnobbhowmik/ton-iot-network-dataset"
_KAGGLE_TARGET_FILE = "Train_Test_Network.csv"

def _ensure_dataset(data_path: str) -> str:
    """Return data_path if it exists; otherwise download from Kaggle and return the CSV path.

    Requires KAGGLE_USERNAME and KAGGLE_KEY environment variables (or ~/.kaggle/kaggle.json).
    kagglehub caches downloads in ~/.cache/kagglehub so the network hit happens only once.
    """
    if os.path.exists(data_path):
        return data_path
    logging.info(
        f"[model] '{data_path}' not found — downloading from Kaggle ({_KAGGLE_SLUG})..."
    )
    try:
        import kagglehub
    except ImportError:
        raise ImportError(
            "kagglehub is required for auto-download. Run: pip install kagglehub>=0.3.0"
        )
    dataset_dir = kagglehub.dataset_download(_KAGGLE_SLUG)
    for root, _, files in os.walk(dataset_dir):
        for fname in files:
            if fname.lower() == _KAGGLE_TARGET_FILE.lower():
                resolved = os.path.join(root, fname)
                logging.info(f"[model] Dataset ready at: {resolved}")
                return resolved
    raise FileNotFoundError(
        f"Downloaded Kaggle dataset to '{dataset_dir}' but "
        f"'{_KAGGLE_TARGET_FILE}' was not found inside it."
    )

# ── Public Helper for Server ──────────────────────────────────────────────────

def get_model_dimensions(data_path: str) -> List[Tuple[int, ...]]:
    """
    Used by main_server.py to initialize global weights with the correct shape.
    """
    data_path = _ensure_dataset(data_path)
    logging.info("[model] Probing dataset to determine feature dimensions...")
    df_sample = pd.read_csv(data_path, nrows=500, low_memory=False)
    _, _, n_features = _preprocess(df_sample)
    dims = [(n_features,), (1,)]
    logging.info(f"[model] Detected model_dimensions: {dims}")
    return dims

# ── Internal Preprocessing ────────────────────────────────────────────────────

def _preprocess(df: pd.DataFrame):
    df = df.copy()

    cols_to_keep = [c for c in FEATURE_COLS if c in df.columns] + [LABEL_COL]
    df = df[cols_to_keep]

    y = df[LABEL_COL].values.astype(np.int32)
    df = df.drop(columns=[LABEL_COL])

    for c in LOG_SCALE_COLS:
        if c in df.columns:
            df[c] = np.log1p(df[c])

    for c in CATEGORICAL_COLS:
        if c in df.columns:
            df[c] = df[c].fillna("unknown").astype(str)
            df[c] = pd.Categorical(df[c], categories=GLOBAL_CATEGORIES[c])

    df = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=False)
    X = df.values.astype(np.float64)

    return X, y, X.shape[1]

# ── Main Model Class ──────────────────────────────────────────────────────────

class LocalLogisticRegressionModel:
    def __init__(
        self,
        client_id: str,
        data_path: str,
        local_epochs: int = 1,
        batch_size: int = 512,
        learning_rate: float = 0.01,
    ):
        self.client_id     = client_id
        self.data_path     = _ensure_dataset(data_path)
        self.local_epochs  = local_epochs
        self.batch_size    = batch_size
        self.learning_rate = learning_rate

        self._partition_idx = CLIENT_PARTITION_MAP[client_id]
        self._scaler        = StandardScaler()
        self._local_round_counter = 0

        # Setup Metrics Logging
        self.metrics_dir = "metrics/results/model"
        os.makedirs(self.metrics_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.metrics_file = os.path.join(self.metrics_dir, f"{self.client_id}_ml_metrics_{timestamp}.csv")
        
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, "w") as f:
                f.write("client_id,fl_round,accuracy,precision,recall,f1,roc_auc,phase\n")

        self._prepare_data_and_pretrain()

    def _prepare_data_and_pretrain(self):
        """Implements the 40% (Pre-train) / 40% (Stream) / 20% (Test) Split"""
        logging.info(f"[{self.client_id}] Initializing data with 40/40/20 split logic...")
        
        df_full = pd.read_csv(self.data_path, low_memory=False)
        # Global shuffle to ensure balanced distribution across the 3 clients
        df_full = df_full.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # 1. Slice the 1/3 portion for this client
        n = len(df_full)
        chunk = n // 3
        start_idx = self._partition_idx * chunk
        end_idx = start_idx + chunk if self._partition_idx < 2 else n
        df_client = df_full.iloc[start_idx:end_idx].reset_index(drop=True)

        # 2. Internal 40/40/20 Split
        n_c = len(df_client)
        idx_pretrain = int(n_c * 0.4)
        idx_stream = int(n_c * 0.8)

        df_pretrain = df_client.iloc[:idx_pretrain]
        df_stream = df_client.iloc[idx_pretrain:idx_stream]
        df_test = df_client.iloc[idx_stream:]

        # 3. Preprocess
        X_pre_raw, self._y_pretrain, self._n_features = _preprocess(df_pretrain)
        X_str_raw, self._y_stream, _ = _preprocess(df_stream)
        X_test_raw, self._y_test, _ = _preprocess(df_test)

        # 4. Scaling (Fit only on pre-train to prevent leakage)
        self._scaler.fit(X_pre_raw)
        self._X_pretrain = self._scaler.transform(X_pre_raw)
        self._X_stream = self._scaler.transform(X_str_raw)
        self._X_test = self._scaler.transform(X_test_raw)

        # 5. Model Initialization & Jump-Start Training
        self._clf = SGDClassifier(
            loss="log_loss",
            learning_rate="constant",
            eta0=self.learning_rate,
            warm_start=True,
            random_state=42
        )

        # Train on the first 40% immediately
        self._clf.partial_fit(self._X_pretrain, self._y_pretrain, classes=[0, 1])
        self._sync_weights_from_clf()
        
        logging.info(f"[{self.client_id}] Pre-training complete on {len(self._X_pretrain)} samples.")

    def fit(self):
        """Called each FL Round: Trains on a new block of the 40% stream."""
        self._local_round_counter += 1
        
        # Determine current block (Assuming approx 5-10 rounds)
        # We slice the 40% stream into chunks based on the round
        total_stream_samples = len(self._X_stream)
        num_expected_rounds = 10 # Safety limit
        block_size = total_stream_samples // num_expected_rounds
        
        effective_round = (self._local_round_counter - 1) % num_expected_rounds
        start = effective_round * block_size
        end = start + block_size if effective_round < num_expected_rounds - 1 else total_stream_samples
        
        X_block = self._X_stream[start:end]
        y_block = self._y_stream[start:end]

        logging.info(f"[{self.client_id}] Round {self._local_round_counter}: Training on stream block [{start}:{end}]")

        if len(X_block) > 0:
            for _ in range(self.local_epochs):
                self._clf.partial_fit(X_block, y_block, classes=[0, 1])

        # Evaluate against the PROTECTED 20% TEST SET
        y_pred = self._clf.predict(self._X_test)
        y_prob = self._clf.predict_proba(self._X_test)[:, 1]

        acc = accuracy_score(self._y_test, y_pred)
        prec = precision_score(self._y_test, y_pred, zero_division=0)
        rec = recall_score(self._y_test, y_pred, zero_division=0)
        f1 = f1_score(self._y_test, y_pred, zero_division=0)
        auc = roc_auc_score(self._y_test, y_prob)

        logging.info(f"[{self.client_id}] Round {self._local_round_counter} Metrics (Unseen Data): Acc={acc:.4f}, F1={f1:.4f}")

        with open(self.metrics_file, "a") as f:
            f.write(f"{self.client_id},{self._local_round_counter},{acc:.6f},"
                    f"{prec:.6f},{rec:.6f},{f1:.6f},{auc:.6f},stream_learning\n")

        self._sync_weights_from_clf()

    def get_weights(self) -> List[np.ndarray]:
        return self.weights

    def set_weights(self, global_weights: List[np.ndarray]):
        if not global_weights: return
        
        new_coef = np.array(global_weights[0], dtype=np.float64).reshape(1, -1)
        new_intercept = np.array(global_weights[1], dtype=np.float64).flatten()

        self._clf.coef_ = new_coef
        self._clf.intercept_ = new_intercept
        self.weights = [new_coef.flatten(), new_intercept]

    def get_model_dimensions(self) -> List[Tuple[int, ...]]:
        return [(self._n_features,), (1,)]

    def _sync_weights_from_clf(self):
        self.weights = [self._clf.coef_.flatten().copy(), self._clf.intercept_.flatten().copy()]

# Alias for system orchestrator
MockSecAggModel = LocalLogisticRegressionModel