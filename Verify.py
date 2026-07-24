import random
import os

def make_fake_der_sig(r_int, s_int):
    r_bytes = r_int.to_bytes((r_int.bit_length() + 7) // 8, 'big')
    s_bytes = s_int.to_bytes((s_int.bit_length() + 7) // 8, 'big')
    
    if r_bytes[0] >= 0x80: r_bytes = b'\x00' + r_bytes
    if s_bytes[0] >= 0x80: s_bytes = b'\x00' + s_bytes
        
    r_block = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    s_block = b'\x02' + bytes([len(s_bytes)]) + s_bytes
    return b'\x30' + bytes([len(r_block) + len(s_block)]) + r_block + s_block

def create_simulated_vulnerabilities():
    print("🛠️ Generating custom test suite hex entries...")
    target_pubkey = "02dc85e49efb668fa962e737bf87515a690757a3e80aa71c4501ddb43ef45b4105"
    
    # Mathematical base integers
    base_r = 0x6d0cb74457ff587ba2df423edb991cf843105a0d33b49ecb2d26f6345ec485d5
    # Shifted variation within the targeted threshold (~1.02 ratio difference)
    shifted_r = int(base_r * 1.02) 
    
    s1, s2, s3 = 0x111111, 0x222222, 0x333333

    sig_identical_1 = make_fake_der_sig(base_r, s1)
    sig_identical_2 = make_fake_der_sig(base_r, s2)
    sig_shifted     = make_fake_der_sig(shifted_r, s3)

    # Base payload formatting arrays
    tx_template = "0100000001{txid}00000000{sig_len}{sig}0121{pubkey}ffffffff01a0860100000000001976a914757c9135398ab776f8090db7f9046c82305df75488ac00000000"

    tx1 = tx_template.format(txid=os.urandom(32).hex(), sig_len=bytes([len(sig_identical_1)+34]).hex(), sig=sig_identical_1.hex(), pubkey=target_pubkey)
    tx2 = tx_template.format(txid=os.urandom(32).hex(), sig_len=bytes([len(sig_identical_2)+34]).hex(), sig=sig_identical_2.hex(), pubkey=target_pubkey)
    tx3 = tx_template.format(txid=os.urandom(32).hex(), sig_len=bytes([len(sig_shifted)+34]).hex(), sig=sig_shifted.hex(), pubkey=target_pubkey)

    with open("raw_transactions.txt", "w") as f:
        f.write(tx1 + "\n" + tx2 + "\n" + tx3 + "\n")
        
    print("✅ Completed! 'raw_transactions.txt' is ready with both identical and shifted signature anomalies.")

if __name__ == "__main__":
    create_simulated_vulnerabilities()
