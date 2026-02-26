import hashlib
from typing import List
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


OP_DUP = 'OP_DUP'
OP_SHA256 = 'OP_SHA256'
OP_EQUALVERIFY = 'OP_EQUALVERIFY'
OP_CHECKSIG = 'OP_CHECKSIG'

# Set of all opcodes for easy checking
OPCODES = {OP_DUP, OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG}


def sha256_hash(data: bytes) -> bytes:
    answer= (sha256(data).digest())
    return answer



def verify_p2pkh(signature: bytes, pubkey: bytes, expected_pubkey_hash: bytes, tx_data: bytes) -> bool:
    if (sha256_hash(pubkey) != expected_pubkey_hash):
        return False
    else:
        try:
            VerifyKey(pubkey).verify(tx_data, signature)
            return True
        except BadSignatureError:
            return False
    # TODO: Implement verify_p2pkh
    # Step 1: Check that sha256_hash(pubkey) == expected_pubkey_hash
    # Step 2: Verify the signature using VerifyKey
    pass


class Script:
    
    def __init__(self, elements: List[str]):
        self.elements = elements

    def to_bytes(self) -> bytes:
        result = b''
        for a in self.elements:
            if a in OPCODES:
                res += a.encode('utf-8')
            else:
                res += bytes.fromhex(a)
        return result
        # TODO: Implement serialization
        

    @staticmethod
    def p2pkh_locking_script(pub_key_hash: str) -> 'Script':
        return Script([OP_DUP, OP_SHA256, pub_key_hash, OP_EQUALVERIFY, OP_CHECKSIG])

    @staticmethod
    def p2pkh_unlocking_script(signature: str, pub_key: str) -> 'Script':
        
        return Script([signature, pub_key])

    def __repr__(self):
        return f"Script({self.elements})"


class ScriptInterpreter:
    """
    [EXTRA CREDIT] Full stack-based Bitcoin script interpreter.

    Executes Bitcoin scripts on a stack. The interpreter processes each element:
    - Opcodes trigger operations on the stack
    - Data elements are pushed onto the stack

    For P2PKH, the combined script (scriptSig + scriptPubKey) executes as:
    1. Push signature (from scriptSig)
    2. Push pubKey (from scriptSig)
    3. OP_DUP: Duplicate pubKey → stack: [sig, pubKey, pubKey]
    4. OP_SHA256: Hash top element → stack: [sig, pubKey, pubKeyHash]
    5. Push expected pubKeyHash (from scriptPubKey) → stack: [sig, pubKey, pubKeyHash, expectedHash]
    6. OP_EQUALVERIFY: Pop two, verify equal → stack: [sig, pubKey]
    7. OP_CHECKSIG: Verify signature → stack: [true/false]

    The script succeeds if the stack is non-empty and the top value is truthy.
    """

    def __init__(self):
        self.stack: List[bytes] = []

    def execute(self, script: Script, tx_data: bytes) -> bool:
        """
        Execute a script. tx_data is used for OP_CHECKSIG.

        Returns True if script succeeds (stack top is truthy), False otherwise.

        Process each element in the script:
        - If it's an opcode, execute the corresponding operation
        - If it's data (hex string), push it onto the stack

        The script succeeds if:
        - No errors occurred during execution
        - The stack is non-empty
        - The top of the stack is truthy (not empty or zero)
        """
        # TODO: Implement script execution
        # Hint: Loop through script.elements, check if each is an opcode or data
        # Use try/except to catch errors and return False
        pass

    def _op_dup(self):
        if not self.stack:
            raise IndexError("OP_DUP: empty stack")
        self.stack.append(self.stack[-1])
        """
        OP_DUP: Duplicate the top stack element.

        Stack: [..., a] -> [..., a, a]
        """
        # TODO: Implement OP_DUP
        pass

    def _op_sha256(self):
        if not self.stack:
            raise IndexError("OP_SHA256: empty stack")
        data = self.stack.pop()
        self.stack.append(sha256_hash(data))

    def _op_equalverify(self) -> bool:
        if len(self.stack) < 2:
            raise IndexError("OP_EQUALVERIFY: need 2 elements")
        b = self.stack.pop()
        a = self.stack.pop()
        if a == b:
            return True
        else:
            raise ValueError("OP_EQUALVERIFY: elements are not equal")

    def _op_checksig(self, tx_data: bytes):
        if len(self.stack) < 2:
            raise IndexError("OP_CHECKSIG: need 2 elements")
        pubkey = self.stack.pop()
        signature = self.stack.pop()
        try:
            VerifyKey(pubkey).verify(tx_data, signature)
            self.stack.append(b'\x01')  # True
        except BadSignatureError:
            self.stack.append(b'\x00')  # False
        # TODO: Implement OP_CHECKSIG
        pass
