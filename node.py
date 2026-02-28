def new_chain(self, genesis: Block):
    utxos = {}
    for tx in genesis.txs:
        for i, output in enumerate(tx.outputs):
            utxos[(tx.tx_hash, i)] = output
    blockchain = Blockchain(chain=[genesis], utxos=utxos)
    self.chains.append(blockchain)

def append(self, block: Block) -> bool:
    for c in self.chains:
        last_block = c.chain[-1].pow
        
        if block.prev == last_block:
            if not self.is_valid_block(block, c):
                return False
        
            new_chain = Blockchain(chain=c.chain + [block], utxos=c.utxos.copy())
            
            for tx in block.txs:
                self.update_utxos(new_chain, tx)
            
            self.chains.append(new_chain)
            return True
    
    return False

def build_block(self, txs: List[Transaction]) -> Optional[Block]:
    if isinstance(txs, Transaction):
        txs = [txs]
    
    if not isinstance(txs, list):
        txs = list(txs)

    longest_chain = max(self.chains, key=lambda c: len(c.chain))
    prev_hash = longest_chain.chain[-1].pow
    temp_utxos = longest_chain.utxos.copy()
    
    for i, tx in enumerate(txs):
        if tx.is_coinbase():
            if i != 0:
                return None
        else:
            for inp in tx.inputs:
                input_key = (inp.tx_hash, inp.output_index)
                if input_key not in temp_utxos:
                    return None
                del temp_utxos[input_key]
        
        tx_hash = tx.tx_hash
        for idx, output in enumerate(tx.outputs):
            temp_utxos[(tx_hash, idx)] = output
    
    block = Block(prev_hash, txs)
    block.mine()
    
    return block

def is_transaction_valid(self, tx: Transaction, blockchain: Blockchain, is_coinbase_allowed: bool = False) -> bool:
    if tx.is_coinbase():
        if not is_coinbase_allowed:
            return False
        total_output = sum(out.value for out in tx.outputs)
        if total_output > BLOCK_REWARD:
            return False
        return True
    
    utxos = blockchain.utxos
    
    seen_inputs = set()
    for inp in tx.inputs:
        input_key = (inp.tx_hash, inp.output_index)
        if input_key in seen_inputs:
            return False
        seen_inputs.add(input_key)
    
    total_input = 0
    for inp in tx.inputs:
        x = (inp.tx_hash, inp.output_index)
        if x not in utxos:
            return False
        
        utxo_output = utxos[x]
        if inp.output.value != utxo_output.value:
            return False
        
        total_input += inp.output.value
        
        signature = bytes.fromhex(inp.script_sig.elements[0])
        pubkey = bytes.fromhex(inp.script_sig.elements[1])
        expected_hash = bytes.fromhex(inp.output.script_pubkey.elements[2])
        tx_data = bytes.fromhex(tx.bytes_to_sign())
        
        if not verify_p2pkh(signature, pubkey, expected_hash, tx_data):
            return False
    
    total_output = sum(out.value for out in tx.outputs)
    
    if total_input != total_output:
        return False
    
    return True

def update_utxos(self, blockchain: Blockchain, tx: Transaction):
    for inp in tx.inputs:
        input_key = (inp.tx_hash, inp.output_index)
        if input_key in blockchain.utxos:
            del blockchain.utxos[input_key]
    
    for index, output in enumerate(tx.outputs):
        blockchain.utxos[(tx.tx_hash, index)] = output