import os
import random

def make_fake_der_sig(r_int, s_int):
    """Encodes integers R and S into a strictly valid ASN.1 DER byte structure"""
    r_bytes = r_int.to_bytes((r_int.bit_length() + 7) // 8, 'big')
    s_bytes = s_int.to_bytes((s_int.bit_length() + 7) // 8, 'big')
    
    # ASN.1 DER rule: If the highest bit is set, prepend a zero byte to keep it positive
    if r_bytes[0] >= 0x80: r_bytes = b'\x00' + r_bytes
    if s_bytes[0] >= 0x80: s_bytes = b'\x00' + s_bytes
        
    r_block = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    s_block = b'\x02' + bytes([len(s_bytes)]) + s_bytes
    
    # 0x30 is the ASN.1 sequence header identifier
    der_sig = b'\x30' + bytes([len(r_block) + len(s_block)]) + r_block + s_block
    return der_sig

def generate_vulnerable_hex():
    print("🛠️ Constructing artificial raw transaction hex strings...")
    
    # 1. Define a static, compressed Public Key to target the exact same address
    target_pubkey = bytes.fromhex("02dc85e49efb668fa962e737bf87515a690757a3e80aa71c4501ddb43ef45b4105")
    
    # 2. Define the INTENTIONAL REUSED R VALUE
    reused_r = 0x6d0cb74457ff587ba2df423edb991cf843105a0d33b49ecb2d26f6345ec485d5
    
    # 3. Define two completely different S values (simulating two different transaction messages)
    s_value_tx1 = 0x268579dfdd1844b20464f1d436e2f1c84cb1c62f2d4e73b22cf3315a6b0cfda6
    s_value_tx2 = 0x5a3b79debc1234a10464f1d436e2f1c84cb1c62f2d4e73b22cf3315a6b0abcde2
    
    # 4. Generate the distinct DER signature blocks (appending the standard 0x01 SIGHASH_ALL byte)
    sig1 = make_fake_der_sig(reused_r, s_value_tx1) + b'\x01'
    sig2 = make_fake_der_sig(reused_r, s_value_tx2) + b'\x01'
    
    # 5. Build raw mock Legacy P2PKH Transaction Structures
    # Structure breakdown:
    # [Version (4B)] [InCount (1B)] [PrevTxID (32B)] [VOUT (4B)] [ScriptSigLen (VarInt)] [Sig] [Pubkey] [Sequence (4B)] [OutCount (1B)] ...
    tx_base = (
        "0100000001"                         # Version 1, 1 Input
        "{prev_txid}"                       # Randomized Previous Transaction ID (32 bytes)
        "00000000"                           # Output index 0
        "{script_sig_len}"                   # Total size of the input scriptSig payload
        "{sig_hex}"                          # The ASN.1 DER signature byte stream
        "21"                                 # Push data operator (0x21 = 33 bytes for compressed key)
        "{pubkey_hex}"                       # Our target public key payload
        "ffffffff"                           # Sequence number
        "01"                                 # 1 Output
        "a086010000000000"                   # Satoshis value field (100,000 sats)
        "1976a914757c9135398ab776f8090db7f9046c82305df75488ac" # Standard P2PKH scriptPubKey template
        "00000000"                           # Locktime parameters
    )
    
    # Compute varying data lengths dynamically
    len_script_sig1 = len(sig1) + 1 + len(target_pubkey) # +1 for the pubkey push byte (0x21)
    len_script_sig2 = len(sig2) + 1 + len(target_pubkey)
    
    # Inject variable pieces to assemble unique hex payloads containing identical R flags
    tx1_hex = tx_base.format(
        prev_txid=os.urandom(32).hex(),
        script_sig_len=bytes([len_script_sig1]).hex(),
        sig_hex=sig1.hex(),
        pubkey_hex=target_pubkey.hex()
    )
    
    tx2_hex = tx_base.format(
        prev_txid=os.urandom(32).hex(),
        script_sig_len=bytes([len_script_sig2]).hex(),
        sig_hex=sig2.hex(),
        pubkey_hex=target_pubkey.hex()
    )
    
    # Write directly to your test input file 
    with open("raw_transactions.txt", "w") as f:
        f.write(tx1_hex + "\n")
        f.write(tx2_hex + "\n")
        
    print("✅ Success! 'raw_transactions.txt' created with 2 targeted matching-r hex samples.")

if __name__ == "__main__":
    generate_vulnerable_hex()
