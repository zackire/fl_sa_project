import os
import math
from concurrent.futures import ThreadPoolExecutor
from typing import cast

import numpy as np
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import pad, unpad
from crypto.interface import CryptoInterface 

# ------------ Flower framework Source Code Starts ------------

# --- Shamir's Secret Sharing Scheme (SSSS) ---

def create_shares(secret: bytes, threshold: int, num: int) -> list[bytes]:
    """Return a list of shares (bytes)."""
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
        recon_arr = arr.view(np.ndarray).astype(float)
        recon_arr = recon_arr * quantizer + shift
        reverse_quantized_list.append(recon_arr)
    return reverse_quantized_list

# ------------ Flower framework Source Code End ------------


# ------------ Custom Secure Aggregation Adapter ------------

# --- PRG Expansion ---

def generate_crypto_prg_mask(
    crypto_stack: CryptoInterface,
    shared_secret: bytes, 
    num_range: int, 
    dimensions_list: list[tuple[int, ...]]
) -> list[np.ndarray]:
    """
    Cryptographically secure pseudo-random number generator for weight masking.
    Maps the raw byte stream from the active CryptoStack into the required Numpy shapes.
    """
    # 1. Calculate the total number of parameters across all model layers
    total_elements = 0
    for dim in dimensions_list:
        total_elements += math.prod(dim) if len(dim) > 0 else 1
        
    # 2. We use 8 bytes (64 bits) per parameter to map cleanly to np.int64
    mask_length = int(total_elements * 8)
    
    # 3. Call the active cryptographic stack to generate raw keystream bytes
    raw_mask_bytes = crypto_stack.generate_prg_mask(shared_secret, mask_length)
    
    # 4. Interpret the raw bytes as a flat 1D array of integers
    flat_mask_array = np.frombuffer(raw_mask_bytes, dtype=np.int64)
    
    # 5. Apply the modulo operation to keep numbers within the secure finite field
    # np.abs guarantees positive values for strict modulo arithmetic
    flat_mask_array = np.abs(flat_mask_array) % num_range
    
    # 6. Slice and reshape the flat array back into the original layer dimensions
    output_tensors = []
    current_idx = 0
    for dim in dimensions_list:
        if len(dim) == 0:
            output_tensors.append(np.array(flat_mask_array[current_idx]))
            current_idx += 1
        else:
            num_items = math.prod(dim)
            layer_mask = flat_mask_array[current_idx : current_idx + num_items].reshape(dim)
            output_tensors.append(layer_mask)
            current_idx += num_items
            
    return output_tensors

# ------------ Custom Secure Aggregation Adapter End ------------