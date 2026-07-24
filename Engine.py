import hashlib
import struct
import psutil
from ecdsa import util, SECP256k1

INPUT_HEX_FILE = "raw_transactions.txt"
VULN_FILE = "vulnerabilities.txt"
IDENTICAL_R_FILE = "identical_r_signatures.txt"

SIGNATURES_DB = []

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a", encoding="utf-8") as f:
        f.write(linia + "\n")

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def base58_encode(payload):
    digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(payload, 'big')
    result = ""
    while value > 0:
        value, mod = divmod(value, 58)
        result = digits[mod] + result
    for byte in payload:
        if byte == 0: result = digits[0] + result
        else: break
    return result

def pubkey_to_address(pubkey_bytes):
    try:
        sha = hashlib.sha256(pubkey_bytes).digest()
        h = hashlib.new('ripemd160', sha).digest()
        version_payload = b'\x00' + h
        return base58_encode(version_payload + sha256d(version_payload)[:4])
    except:
        return "UnknownAddress"

def parse_varint(data, offset):
    if offset >= len(data): return 0, offset
    prefix = data[offset]
    offset += 1
    if prefix < 0xfd: return prefix, offset
    elif prefix == 0xfd: return int.from_bytes(data[offset:offset+2], 'little'), offset+2
    elif prefix == 0xfe: return int.from_bytes(data[offset:offset+4], 'little'), offset+4
    return int.from_bytes(data[offset:offset+8], 'little'), offset+8

def analyze_signature(sig_data):
    """Core evaluation engine that logs duplicates immediately"""
    global SIGNATURES_DB
    new_r_int = int(sig_data["r"], 16)
    
    print(f"    🔎 Processing R: {sig_data['r'][:12]}... Address: {sig_data['address']}")
    
    for old_sig in SIGNATURES_DB:
        if old_sig["txid"] == sig_data["txid"]: 
            continue
            
        old_r_int = int(old_sig["r"], 16)
        if old_r_int == 0: 
            continue
            
        # 1. Exact Duplicate Verification
        if sig_data["r"] == old_sig["r"]:
            line = (
                f"txid1: {old_sig['txid']}\naddress1: {old_sig['address']}\n"
                f"r: {old_sig['r']}\ns1: {old_sig['s']}\n"
                f"txid2: {sig_data['txid']}\naddress2: {sig_data['address']}\n"
                f"r: {sig_data['r']}\ns2: {sig_data['s']}\n"
                "----------------------------------"
            )
            zapisz_do_pliku(IDENTICAL_R_FILE, line)
            print(f"💥 SUCCESS: Written duplicate pattern to {IDENTICAL_R_FILE}")
            
        # 2. Ratio Delta Check
        elif sig_data["address"] == old_sig["address"]:
            ratio = new_r_int / old_r_int if new_r_int >= old_r_int else old_r_int / new_r_int
            if 0.9 <= ratio <= 1.1:
                line = f"txid1: {old_sig['txid']}\nAddress: {sig_data['address']}\nRatio: {ratio:.4f}\n----------------"
                zapisz_do_pliku(VULN_FILE, line)
                print(f"🚨 ALERT: Variance written to {VULN_FILE}")

    SIGNATURES_DB.append(sig_data)

def process_transaction(raw_tx_hex):
    """Extracts cryptographic targets sequentially out of standard streams"""
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex.strip())
        txid = sha256d(tx_bytes)[::-1].hex()
    except:
        return

    offset = 4
    try:
        # Check for SegWit Marker
        if tx_bytes[offset] == 0x00 and tx_bytes[offset+1] != 0x00:
            # Skip marker/flag
            offset += 2
            
        vin_count, offset = parse_varint(tx_bytes, offset)
        for _ in range(vin_count):
            offset += 36  # Previous TxOutpoint
            slen, offset = parse_varint(tx_bytes, offset)
            script_sig = tx_bytes[offset-slen:offset]
            offset += 4   # Sequence
            
            if b'\x30' in script_sig:
                s_idx = script_sig.index(b'\x30')
                total_len = script_sig[s_idx+1] + 2
                sig_bytes = script_sig[s_idx:s_idx+total_len]
                
                # Dynamically check for trailing compressed key boundary
                pk_start = s_idx + total_len + 1
                pk_bytes = script_sig[pk_start:pk_start+33]
                
                if len(pk_bytes) == 33 and pk_bytes[0] in [0x02, 0x03]:
                    # Extract raw parameters cleanly
                    r, s = util.sigdecode_der(sig_bytes[:-1], SECP256k1.order)
                    
                    sig_data = {
                        "txid": txid,
                        "address": pubkey_to_address(pk_bytes),
                        "pubkey": pk_bytes.hex(),
                        "r": hex(r)[2:].zfill(64),
                        "s": hex(s)[2:].zfill(64)
                    }
                    analyze_signature(sig_data)
    except Exception as e:
        pass

def main():
    print(f"🚀 Initializing Stable Offline Engine...")
    try:
        with open(INPUT_HEX_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        print(f"🔍 Reading {len(lines)} hex inputs from '{INPUT_HEX_FILE}'...")
        for idx, line in enumerate(lines):
            process_transaction(line)
            
        print("✅ Scan finished.")
    except FileNotFoundError:
        print(f"❌ Input source layout file '{INPUT_HEX_FILE}' is missing.")

if __name__ == "__main__":
    main()
