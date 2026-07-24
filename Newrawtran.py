import hashlib
import struct
import psutil
import re
from ecdsa import util, SECP256k1

# Configuration and Output Files
INPUT_HEX_FILE = "raw_transactions.txt"
VULN_FILE = "vulnerabilities.txt"
IDENTICAL_R_FILE = "identical_r_signatures.txt"

SIGNATURES = []

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a", encoding="utf-8") as f:
        f.write(linia + "\n")

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def check_memory_usage():
    mem = psutil.virtual_memory()
    if mem.percent >= 90:
        print(f"⚠️ RAM użycie {mem.percent}% – czyszczenie cache podpisów.")
        SIGNATURES.clear()

def save_vulnerability(sig1, sig2, ratio):
    line = (
        f"txid1: {sig1['txid']}\naddress: {sig1['address']}\npubkey: {sig1['pubkey']}\n"
        f"r1: {sig1['r']}\ns1: {sig1['s']}\nz1: {sig1['z']}\n"
        f"txid2: {sig2['txid']}\naddress2: {sig2['address']}\npubkey2: {sig2['pubkey']}\n"
        f"r2: {sig2['r']}\ns2: {sig2['s']}\nz2: {sig2['z']}\nRatio: {ratio:.4f}\n"
        "----------------------------------"
    )
    zapisz_do_pliku(VULN_FILE, line)
    print(f"🚨 WYKRYTO PODOBNE r DLA TEGO SAMEGO ADRESU (Ratio: {ratio:.4f})")

def save_identical_r_signature(sig1, sig2):
    line = (
        f"txid1: {sig1['txid']}\naddress1: {sig1['address']}\npubkey1: {sig1['pubkey']}\n"
        f"r: {sig1['r']}\ns1: {sig1['s']}\nz1: {sig1['z']}\n"
        f"txid2: {sig2['txid']}\naddress2: {sig2['address']}\npubkey2: {sig2['pubkey']}\n"
        f"r: {sig2['r']}\ns2: {sig2['s']}\nz2: {sig2['z']}\n"
        "----------------------------------"
    )
    zapisz_do_pliku(IDENTICAL_R_FILE, line)
    print(f"⚠️ ZNALEZIONO IDENTYCZNE r IN TX: {sig2['txid']}")

def analyze_signature(new_sig):
    check_memory_usage()
    if not new_sig["r"]:
        return
    
    new_r_int = int(new_sig["r"], 16)
    for old_sig in SIGNATURES:
        if old_sig["txid"] == new_sig["txid"]:
            continue
            
        old_r_int = int(old_sig["r"], 16)
        if old_r_int == 0:
            continue
            
        if new_sig["r"] == old_sig["r"]:
            save_identical_r_signature(old_sig, new_sig)
        elif new_sig["address"] == old_sig["address"]:
            ratio = new_r_int / old_r_int if new_r_int >= old_r_int else old_r_int / new_r_int
            if 0.9 <= ratio <= 1.1:
                save_vulnerability(old_sig, new_sig, ratio)
                
    SIGNATURES.append(new_sig)

def pubkey_to_address(pubkey_bytes):
    """Generates a standard Legacy P2PKH Bitcoin Address from Public Key Bytes"""
    try:
        sha = hashlib.sha256(pubkey_bytes).digest()
        h = hashlib.new('ripemd160')
        h.update(sha)
        pubkey_hash = h.digest()
        
        version_payload = b'\x00' + pubkey_hash
        checksum = sha256d(version_payload)[:4]
        full_payload = version_payload + checksum
        
        digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        value = int.from_bytes(full_payload, 'big')
        result = ""
        while value > 0:
            value, mod = divmod(value, 58)
            result = digits[mod] + result
            
        for byte in full_payload:
            if byte == 0:
                result = digits[0] + result
            else:
                break
        return result
    except Exception:
        return "UnknownAddress"

def extract_sigs_and_keys(raw_tx_hex):
    """Robust offline extraction of signatures and keys from a raw hex string"""
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex.strip())
        txid = sha256d(tx_bytes)[::-1].hex()
    except Exception:
        return

    # Find DER Signatures using regex matching DER pattern: 30 [total_len] 02 [r_len] r_bytes 02 [s_len] s_bytes
    # Standard length ranges from 68 to 73 bytes
    der_pattern = re.compile(b'\x30[\x44-\x49]\x02[\x1f-\x21].*?\x02[\x1f-\x21].*?')
    found_sigs = der_pattern.findall(tx_bytes)

    # Find Compressed Public Keys (33 bytes starting with 02 or 03)
    pubkey_pattern = re.compile(b'[\x02\x03][\x00-\xff]{32}')
    found_keys = pubkey_pattern.findall(tx_bytes)

    if found_sigs:
        print(f"  Found {len(found_sigs)} signature(s) in TX ID: {txid}")
        
        for idx, sig_bytes in enumerate(found_sigs):
            try:
                # Clean up if trailing sighash flag was appended inside regex capture
                if len(sig_bytes) > 2 and sig_bytes[1] + 2 < len(sig_bytes):
                    sig_bytes = sig_bytes[:sig_bytes[1] + 2]

                r, s = util.sigdecode_der(sig_bytes, SECP256k1.order)
                
                # Pair with corresponding public key if found, otherwise use fallback
                pub_bytes = found_keys[idx] if idx < len(found_keys) else b''
                address = pubkey_to_address(pub_bytes) if pub_bytes else "UnknownAddress"
                
                # Offline Z placeholder (Requires full TX serialization tree for accuracy)
                z_val = hashlib.sha256(sig_bytes).hexdigest()

                sig_data = {
                    "txid": txid,
                    "address": address,
                    "pubkey": pub_bytes.hex() if pub_bytes else "N/A",
                    "r": hex(r)[2:],
                    "s": hex(s)[2:],
                    "z": z_val
                }
                
                print(f"    -> Parsed r: {sig_data['r'][:10]}... Address: {address}")
                analyze_signature(sig_data)
                
            except Exception as e:
                continue

def main():
    print(f"🚀 Loading raw hex strings from {INPUT_HEX_FILE}...")
    try:
        with open(INPUT_HEX_FILE, "r") as f:
            lines = f.readlines()
        
        print(f"🔍 Processing {len(lines)} transactions offline...")
        for line in lines:
            if line.strip():
                extract_sigs_and_keys(line.strip())
                
        print("✅ Offline matching run complete.")
    except FileNotFoundError:
        print(f"❌ Error: Create '{INPUT_HEX_FILE}' and paste your transaction hex lines inside.")

if __name__ == "__main__":
    main()
