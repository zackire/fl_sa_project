import os
import math
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

import numpy as np
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import pad, unpad

# ------------ Flower framework Source Code Starts ------------

# --- Shamir's Secret Sharing Scheme (SSSS) ---

def create_shares(secret: bytes, threshold: int, num: int) -> list[bytes]:
    """Return a list of shares (bytes)."""
    if secret is None:
        raise ValueError("Secret cannot be None.")
    secret_padded = pad(secret, 16)
    chunks = [secret_padded[i : i + 16] for i in range(0, len(secret_padded), 16)]
    share_list: list[bytearray] = [bytearray() for _ in range(num)]
    max_workers = min(len(chunks), os.cpu_count() or 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for chunk_shares in executor.map(
            lambda chunk: _shamir_split(threshold, num, chunk), chunks
        ):
            for idx, share in chunk_shares:
                if not share_list[idx - 1]:
                    share_list[idx - 1] += idx.to_bytes(4, "little", signed=False)
                share_list[idx - 1] += share
    return [bytes(share) for share in share_list]

def _shamir_split(threshold: int, num: int, chunk: bytes) -> list[tuple[int, bytes]]:
    return Shamir.split(threshold, num, chunk, ssss=False)

def combine_shares(share_list: list[bytes]) -> bytes:
    """Reconstruct the secret from a list of shares."""
    if not share_list:
        raise ValueError("Share list cannot be None or empty.")
    for share in share_list:
        if share is None:
            raise ValueError("Individual share cannot be None.")
    chunk_num = (len(share_list[0]) - 4) >> 4
    secret_padded = bytearray(0)
    chunk_shares_list: list[list[tuple[int, bytes]]] = [[] for _ in range(chunk_num)]
    for share in share_list:
        index = int.from_bytes(share[:4], "little", signed=False)
        for i in range(chunk_num):
            start = (i << 4) + 4
            chunk_shares_list[i].append((index, share[start : start + 16]))
    max_workers = min(chunk_num, os.cpu_count() or 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for chunk in executor.map(_shamir_combine, chunk_shares_list):
            secret_padded += chunk
    try:
        secret = unpad(bytes(secret_padded), 16)
    except ValueError:
        raise ValueError("Failed to combine shares") from None
    return secret

def _shamir_combine(shares: list[tuple[int, bytes]]) -> bytes:
    return Shamir.combine(shares, ssss=False)


# --- Quantization ---

def _stochastic_round(arr: np.ndarray) -> np.ndarray:
    ret = np.ceil(arr).astype(np.int32)
    rand_arr = np.random.rand(*ret.shape)
    if len(ret.shape) == 0:
        if rand_arr < ret - arr:
            ret -= 1
    else:
        ret[rand_arr < ret - arr] -= 1
    return ret

def quantize(
    parameters: list[np.ndarray], clipping_range: float, target_range: int
) -> list[np.ndarray]:
    """Quantize float Numpy arrays to integer Numpy arrays."""
    quantized_list: list[np.ndarray] = []
    quantizer = target_range / (2 * clipping_range)
    for arr in parameters:
        pre_quantized = (np.clip(arr, -clipping_range, clipping_range) + clipping_range) * quantizer
        quantized = _stochastic_round(pre_quantized)
        quantized_list.append(quantized)
    return quantized_list

def dequantize(
    quantized_parameters: list[np.ndarray],
    clipping_range: float,
    target_range: int,
) -> list[np.ndarray]:
    """Dequantize integer Numpy arrays to float Numpy arrays."""
    reverse_quantized_list: list[np.ndarray] = []
    quantizer = (2 * clipping_range) / target_range
    shift = -clipping_range
    for arr in quantized_parameters:
        # Replaced arr.view(np.ndarray) with np.array(arr) to safely accept our flat lists
        recon_arr = np.array(arr).astype(float)
        recon_arr = recon_arr * quantizer + shift
        reverse_quantized_list.append(recon_arr)
    return reverse_quantized_list


# ------------ Flower framework Source Code End ------------


# ==========================================
# CUSTOM SECURE AGGREGATION ADAPTERS
# (Bridges the ML arrays and the CryptoInterface lists)
# ==========================================

def get_model_dimensions(parameters: List[np.ndarray]) -> List[Tuple[int, ...]]:
    """Extracts the exact structural dimensions of the ML model."""
    if parameters is None:
        raise ValueError("parameters cannot be None")
    return [arr.shape for arr in parameters]

def flatten_ndarrays_to_list(parameters: List[np.ndarray]) -> List[float]:
    """
    Translates the ML multi-dimensional arrays into the flat 1D list 
    required by the CryptoInterface.
    """
    if parameters is None:
        raise ValueError("parameters cannot be None")
    flat_list = []
    for arr in parameters:
        flat_list.extend(arr.flatten().tolist())
    return flat_list

def reshape_list_to_ndarrays(flat_vector: List[float], dimensions: List[Tuple[int, ...]]) -> List[np.ndarray]:
    """
    Reconstructs the flat cryptographic output back into the 
    original multi-dimensional ML model structure.
    """
    if flat_vector is None or dimensions is None:
        raise ValueError("Inputs cannot be None")
    output_tensors = []
    current_idx = 0
    
    for dim in dimensions:
        if len(dim) == 0:
            # Handles scalar values
            output_tensors.append(np.array(flat_vector[current_idx]))
            current_idx += 1
        else:
            num_items = math.prod(dim)
            layer_data = flat_vector[current_idx : current_idx + num_items]
            reshaped_array = np.array(layer_data).reshape(dim)
            output_tensors.append(reshaped_array)
            current_idx += num_items
            
    return output_tensors