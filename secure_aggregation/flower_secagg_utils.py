import os
from concurrent.futures import ThreadPoolExecutor
from typing import cast

import numpy as np
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import pad, unpad

# --- Shamir Secret Sharing ---

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


# --- PRG Expansion ---

def pseudo_rand_gen(
    seed: bytes, num_range: int, dimensions_list: list[tuple[int, ...]]
) -> list[np.ndarray]:
    """Seeded pseudo-random number generator for noise generation with Numpy."""
    assert len(seed) & 0x3 == 0
    seed32 = 0
    for i in range(0, len(seed), 4):
        seed32 ^= int.from_bytes(seed[i : i + 4], "little")
    gen = np.random.RandomState(seed32)
    output = []
    for dimension in dimensions_list:
        if len(dimension) == 0:
            arr = np.array(gen.randint(0, num_range - 1), dtype=np.int64)
        else:
            arr = gen.randint(0, num_range - 1, dimension, dtype=np.int64)
            
        output.append(arr)
    return output
