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
    if len(tx_hashes) == 0:
        return double_sha256(b'').hex()
    elif len(tx_hashes) == 1:
        return tx_hashes[0]

    i = 0
    while(len(tx_hashes) > 1):
        if i + 1 < len(tx_hashes): 
            new = tx_hashes[i] + tx_hashes[i+1]
            new = unhexlify(new)
            new = double_sha256(new).hex()
            tx_hashes[i] = new
            tx_hashes.pop(i+1)
            i += 1
        else:
            new = tx_hashes[i] + ZERO_HASH
            new = unhexlify(new)
            new = double_sha256(new).hex()
            tx_hashes[i] = new
            i = 0
        if i >= len(tx_hashes):  
            i = 0

    return tx_hashes[0]


def merkle_proof(tx_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    res = []
    i = 0

    if index % 2 == 0:
        res.append((tx_hashes[index+1], 'right'))
        index = index // 2
    elif index % 2 != 0:
        res.append((tx_hashes[index-1], 'left'))
        index = index // 2

    while(len(tx_hashes) > 1):
        if i + 1 < len(tx_hashes): 
            new = tx_hashes[i] + tx_hashes[i+1]
            new = unhexlify(new)
            new = double_sha256(new).hex()
            tx_hashes[i] = new
            tx_hashes.pop(i+1)
            i += 1
        else:
            new = tx_hashes[i] + ZERO_HASH
            new = unhexlify(new)
            new = double_sha256(new).hex()
            tx_hashes[i] = new
            i = 0
            index = index // 2
            if index % 2 == 0:
                res.append((tx_hashes[index+1], 'right'))
                index = index // 2
            elif index % 2 != 0:
                res.append((tx_hashes[index-1], 'left'))
                index = index // 2
    return res


def verify_merkle_proof(tx_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    if len(proof) == 0:
        return tx_hash == root
    a = tx_hash
    for i in range(0, len(proof)):
        if proof[i][1] == 'left':
            a = proof[i][0] + a 
        else:
            a = a + proof[i][0]
        a = unhexlify(a)
        a = double_sha256(a).hex()
    return a == root
    
