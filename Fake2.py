import os

def make_fake_der_sig(r_int, s_int):
    """Strict, Python 3-safe ASN.1 DER signer block"""
    r_bytes = r_int.to_bytes((r_int.bit_length() + 7) // 8, 'big')
    s_bytes = s_int.to_bytes((s_int.bit_length() + 7) // 8, 'big')
    
    # Safe multi-byte check
    if r_bytes[0] >= 0x80: r_bytes = b'\x00' + r_bytes
    if s_bytes[0] >= 0x80: s_bytes = b'\x00' + s_bytes
        
    r_block = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    s_block = b'\x02' + bytes([len(s_bytes)]) + s_bytes
    
    return b'\x30' + bytes([len(r_block) + len(s_block)]) + r_block + s_block

def run_suite():
    print("🛠️ Packaging heterogeneous multi-format test vectors...")
    
    # Test Public Keys
    comp_pk = "02dc85e49efb668fa962e737bf87515a690757a3e80aa71c4501ddb43ef45b4105"
    uncomp_pk = "046a0f757c9135398ab776f8090db7f9046c82305df75488ac757c9135398ab776f8090db7f9046c82305df75488ac757c9135398ab776f8090db7f9046c82305df7"
    
    reused_r = 0x6d0cb74457ff587ba2df423edb991cf843105a0d33b49ecb2d26f6345ec485d5
    s1, s2 = 0xabcde12345, 0x98765fedcb

    sig1 = make_fake_der_sig(reused_r, s1) + b'\x01'
    sig2 = make_fake_der_sig(reused_r, s2) + b'\x01'

    # Compute explicit string sizes (1 byte for push code + signature length + 1 byte push code + pubkey length)
    slen1 = 1 + len(sig1) + 1 + 33
    slen2 = 1 + len(sig2) + 1 + 65

    # Safe hexadecimal formatting string padding (zfill)
    slen1_hex = hex(slen1)[2:].zfill(2)
    slen2_hex = hex(slen2)[2:].zfill(2)

    sig1_push = hex(len(sig1))[2:].zfill(2)
    sig2_push = hex(len(sig2))[2:].zfill(2)

    tx_template = "0100000001{txid}00000000{slen}{sig_push}{sig}{klen}{pk}ffffffff01a0860100000000001976a914757c9135398ab776f8090db7f9046c82305df75488ac00000000"

    tx1 = tx_template.format(txid=os.urandom(32).hex(), slen=slen1_hex, sig_push=sig1_push, sig=sig1.hex(), klen="21", pk=comp_pk)
    tx2 = tx_template.format(txid=os.urandom(32).hex(), slen=slen2_hex, sig_push=sig2_push, sig=sig2.hex(), klen="41", pk=uncomp_pk)

    with open("raw_transactions.txt", "w") as f:
        f.write(tx1 + "\n" + tx2 + "\n")
    print("✅ Completed layout serialization tracking file creation.")

if __name__ == "__main__":
    run_suite()
