import hashlib
from typing import Optional, List

from transaction import Transaction, DIFFICULTY
from merkle import build_merkle_tree



class Block:
    """
    A block on a blockchain. Prev is a string that contains the hex-encoded hash
    of the previous block. Contains a list of transactions.
    """

    def __init__(self, prev: str, txs: List[Transaction], nonce: Optional[str]):
        self.txs = txs
        self.nonce = nonce
        self.prev = prev
        self.pow = None

    def get_merkle_root(self) -> str:
        """Compute the Merkle root of all transactions in the block."""
        tx_hashes = [tx.tx_hash for tx in self.txs]
        return build_merkle_tree(tx_hashes)

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):

        temp_nonce = 0
        self.nonce = temp_nonce.to_bytes(4, byteorder='big').hex()
        while int(self.hash(), 16) > DIFFICULTY:
            temp_nonce += 1
            self.nonce = temp_nonce.to_bytes(4, byteorder='big').hex()
        self.pow = self.hash()
       
        # TODO: Implement mining
        # Hint: Increment nonce until hash() returns a value <= DIFFICULTY
        # Hint: Once found, store the hash in self.pow
        

    # Hash the block header (prev + merkle_root + nonce)
    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.get_merkle_root()))
        m.update(bytes.fromhex(self.nonce))

        return m.hexdigest()