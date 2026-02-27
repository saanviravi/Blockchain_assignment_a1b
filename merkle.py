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


def build_merkle_tree(tx_hashes: List[str]) -> str:
    """Build a Merkle tree and return the root hash."""
    if len(tx_hashes) == 0:
        return double_sha256(b'').hex()

    hashes = tx_hashes.copy()
    
    if len(hashes) == 1:
        return hashes[0]

    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(ZERO_HASH)
        
        next_level = []
        for i in range(0, len(hashes), 2):
            parent = merkle_parent(hashes[i], hashes[i + 1])
            next_level.append(parent)
        
        hashes = next_level

    return hashes[0]


def merkle_proof(tx_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """Generate a Merkle proof for the transaction at the given index."""
    if len(tx_hashes) <= 1:
        return []
    

    hashes = tx_hashes.copy()
    proof = []
    
    while len(hashes) > 1:
     
        if len(hashes) % 2 != 0:
            hashes.append(ZERO_HASH)
    
        if index % 2 == 0:
       
            sibling = hashes[index + 1]
            proof.append((sibling, 'right'))
        else:

            sibling = hashes[index - 1]
            proof.append((sibling, 'left'))
        
  
        next_level = []
        for i in range(0, len(hashes), 2):
            parent = merkle_parent(hashes[i], hashes[i + 1])
            next_level.append(parent)
        
        hashes = next_level
        index = index // 2

    return proof


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