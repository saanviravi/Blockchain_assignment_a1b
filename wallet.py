from typing import List, Optional
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
import hashlib
from hashlib import sha256
from script import Script, sha256_hash
from transaction import Input, Output, Transaction

"""
Wallet functionality for building and signing transactions.
"""


def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    """
    Build and sign a transaction with the given inputs and outputs.

    This creates P2PKH unlocking scripts (scriptSig) for each input.
    Returns None if impossible to build a valid transaction.
    Does not verify that inputs are unspent.

    Validation checks:
    - Inputs and outputs must not be empty
    - All inputs must be spendable by the signing key (pub_key_hash matches)
    - Input values must equal output values
    - No duplicate inputs (same txid)

    Steps:
    1. Validate inputs and outputs
    2. Check that the signing key can spend all inputs
    3. Create an unsigned transaction (empty scriptSigs)
    4. Sign the transaction data
    5. Create scriptSig for each input with signature and public key
    6. Return the signed transaction
    """
    # TODO: Implement build_transaction
    # Hint: Use Script.p2pkh_unlocking_script(signature, pub_key) for scriptSig
    
    
    if not inputs:
        return None
    if not outputs:
        return None
    seen=set()
    for item in inputs:
        if item.tx_hash in seen:
            return None
        seen.add(item.tx_hash)

    pub_key=signing_key.verify_key.encode(encoder=HexEncoder).decode()
    pub_key_hash=sha256_hash(bytes.fromhex(pub_key)).hex()
    for inp in inputs:
        if pub_key_hash!=inp.output.script_pubkey.elements[2]:
            return None

    if sum(inp.output.value for inp in inputs)!=sum(out.value for out in outputs):
        return None
    
    unsigned_tx = Transaction(inputs, outputs)
    bytes_sign = unsigned_tx.bytes_to_sign()
    signature = signing_key.sign(bytes.fromhex(bytes_sign), encoder=HexEncoder).signature.decode()
    signed_inp=[]
    for inp in inputs:
        script_sig=Script.p2pkh_unlocking_script(signature, pub_key)
        new_inp = Input(inp.output, inp.tx_hash, script_sig)
        signed_inp.append(new_inp)
        

    return Transaction(signed_inp, outputs)

    

    

    

    
    
