import hashlib
import binascii
from typing import List, Tuple, Optional
from hashlib import sha256
from binascii import hexlify
from binascii import unhexlify

ZERO_HASH = '0' * 64


def double_sha256(data: bytes) -> bytes:
    answer = (sha256(sha256(data).digest()).digest())
    return answer


def merkle_parent(left: str, right: str) -> str:
    concatenated = unhexlify(left) + unhexlify(right)
    result = hexlify(double_sha256(concatenated)).decode()
    return result


def build_merkle_tree(tx_hashes):
    if len(tx_hashes) == 0:
        return double_sha256(b'').hex()
    
    if len(tx_hashes) == 1:
        return tx_hashes[0]
    
    temp_hashes = tx_hashes.copy()
    
    if len(temp_hashes) % 2 != 0:
        temp_hashes.append(ZERO_HASH)
    
    result = []
    for i in range(0, len(temp_hashes), 2):
        concat = temp_hashes[i] + temp_hashes[i + 1]
        parent = double_sha256(bytes.fromhex(concat)).hex()
        result.append(parent)
    
    return build_merkle_tree(result)
#logic referenced from learnmeabitcoin.com, with changes necessary to fit this assignment. 


def merkle_proof(tx_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """Generate a Merkle proof for the transaction at the given index."""
    
    if len(tx_hashes) <= 1:
        return []
    
    temp_hashes = tx_hashes.copy()
    
    if len(temp_hashes) % 2 != 0:
        temp_hashes.append(ZERO_HASH)
    
    if index % 2 == 0:
        sibling = temp_hashes[index + 1]
        direction = 'right'
    else:
        sibling = temp_hashes[index - 1]
        direction = 'left'
    
    next_level = []
    for i in range(0, len(temp_hashes), 2):
        parent = merkle_parent(temp_hashes[i], temp_hashes[i + 1])
        next_level.append(parent)
    
    return [(sibling, direction)] + merkle_proof(next_level, index // 2)



def verify_merkle_proof(tx_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """Verify a Merkle proof."""
    if len(proof) == 0:
        return tx_hash == root
    
    current = tx_hash
    for sibling, direction in proof:
        if direction == 'left':
            current = merkle_parent(sibling, current)
        else:
            current = merkle_parent(current, sibling)
    
    return current == root