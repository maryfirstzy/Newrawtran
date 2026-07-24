import random
import hashlib

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def make_fake_der_sig(r_hex, s_hex):
    """Encodes raw R and S hex values into a valid ASN.1 DER byte structure"""
    r_bytes = bytes.fromhex(r_hex)
    s_bytes = bytes.fromhex(s_hex)
    
    # Pad with a zero byte if the highest bit is set (standard DER rule)
    if r_bytes[0] >= 0x80: r_bytes = b'\x00' + r_bytes
    if s_bytes[0] >= 0x80: s_bytes = b'\x00' + s_bytes
        
    r_block = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    s_block = b'\x02' + bytes([len(s_bytes)]) + s_bytes
    
    der_sig = b'\x30' + bytes([len(r_block) + len(s_block)]) + r_block + s_block
    return der_sig

def generate_test_file():
    # A real compressed public key for a valid legacy address representation
    target_pubkey = "02dc85e49efb668fa962e737bf87515a690757a3e80aa71c4501ddb43ef45b4105"
    
    # The signature parameters we want to reuse across multiple transactions
    shared_r = "6d0cb74457ff587ba2df423edb991cf843105a0d33b49ecb2d26f6345ec485d5"
    fake_s1  = "1111111111111111111111111111111111111111111111111111111111111111"
    fake_s2  = "2222222222222222222222222222222222222222222222222222222222222222"
    
    sig1_bytes = make_fake_der_sig(shared_r, fake_s1)
    sig2_bytes = make_fake_der_sig(shared_r, fake_s2)
    
    # Construct base mock legacy P2PKH transactions
    # Contains: Version, Input count, Input references, scriptSig injection, Outputs, Locktime
    tx1_hex = f"0100000001{os_random_hex(32)}00000000{bytes([len(sig1_bytes) + 34]).hex()}{sig1_bytes.hex()}0121{target_pubkey}ffffffff01a0860100000000001976a914757c9135398ab776f8090db7f9046c82305df75488ac00000000"
    tx2_hex = f"0100000001{os_random_hex(32)}00000000{bytes([len(sig2_bytes) + 34]).hex()}{sig2_bytes.hex()}0121{target_pubkey}ffffffff01a0860100000000001976a914757c9135398ab776f8090db7f9046c82305df75488ac00000000"
    
    with open("raw_transactions.txt", "w") as f:
        f.write(tx1_hex + "\n")
        f.write(tx2_hex + "\n")
        
    print("✅ Created 'raw_transactions.txt' with 2 transactions intentionally reusing the same 'r' parameter.")

def os_random_hex(length):
    return "".join(random.choices("0123456789abcdef", k=length*2))

if __name__ == "__main__":
    generate_test_file()
