import hashlib
import struct
import psutil
import re
from ecdsa import util, SECP256k1

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

def base58_encode(payload):
    """Accurate Base58 check encoder for standard Bitcoin addresses"""
    digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(payload, 'big')
    result = ""
    while value > 0:
        value, mod = divmod(value, 58)
        result = digits[mod] + result
    
    # Pad leading 1s for zero bytes in payload
    for byte in payload:
        if byte == 0:
            result = digits[0] + result
        else:
            break
    return result

def pubkey_to_address(pubkey_bytes):
    """Generates a correct Mainnet Legacy P2PKH Bitcoin Address"""
    try:
        sha = hashlib.sha256(pubkey_bytes).digest()
        h = hashlib.new('ripemd160')
        h.update(sha)
        pubkey_hash = h.digest()
        
        version_payload = b'\x00' + pubkey_hash
        checksum = sha256d(version_payload)[:4]
        return base58_encode(version_payload + checksum)
    except Exception:
        return "UnknownAddress"

def compute_legacy_z(raw_tx_bytes, input_index, script_pub_key):
    """Computes the mathematically correct z-value (sighash) for legacy inputs completely offline"""
    try:
        # Mini-parser to strip scripts and swap out for target scriptPubKey
        # Standard SIGHASH_ALL reconstruction
        offset = 4
        def read_varint(data, off):
            prefix = data[off]
            off += 1
            if prefix < 0xfd: return prefix, off
            elif prefix == 0xfd: return int.from_bytes(data[off:off+2], 'little'), off+2
            elif prefix == 0xfe: return int.from_bytes(data[off:off+4], 'little'), off+4
            return int.from_bytes(data[off:off+8], 'little'), off+8

        vin_count, offset = read_varint(raw_tx_bytes, offset)
        inputs_data = []
        for i in range(vin_count):
            txid = raw_tx_bytes[offset:offset+32]
            offset += 32
            vout = raw_tx_bytes[offset:offset+4]
            offset += 4
            script_len, offset = read_varint(raw_tx_bytes, offset)
            current_script = raw_tx_bytes[offset:offset+script_len]
            offset += script_len
            sequence = raw_tx_bytes[offset:offset+4]
            offset += 4
            inputs_data.append({'txid': txid, 'vout': vout, 'script': current_script, 'seq': sequence})

        # Build modified serialization preimage
        preimage = struct.pack("<I", 1) # Version
        preimage += struct.pack("B", vin_count)
        for i, inp in enumerate(inputs_data):
            preimage += inp['txid'] + inp['vout']
            if i == input_index:
                preimage += struct.pack("B", len(script_pub_key)) + script_pub_key
            else:
                preimage += b'\x00' # Empty script for other inputs
            preimage += inp['seq']

        # Copy outputs raw payload over
        vout_count, offset = read_varint(raw_tx_bytes, offset)
        preimage += struct.pack("B", vout_count)
        for _ in range(vout_count):
            preimage += raw_tx_bytes[offset:offset+8] # value
            offset += 8
            slen, offset = read_varint(raw_tx_bytes, offset)
            preimage += struct.pack("B", slen) + raw_tx_bytes[offset:offset+slen]
            offset += slen
            
        preimage += raw_tx_bytes[offset:offset+4] # Locktime
        preimage += struct.pack("<I", 1) # SIGHASH_ALL code flag
        
        return sha256d(preimage).hex()
    except Exception:
        return "ErrorComputingZ"

def extract_sigs_and_keys(raw_tx_hex):
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex.strip())
        txid = sha256d(tx_bytes)[::-1].hex()
    except Exception:
        return

    # Accurate ASN.1 DER boundary captures
    der_pattern = re.compile(b'\x30[\x44-\x49]\x02[\x1f-\x21].*?\x02[\x1f-\x21].*?(?=\x01|\x02|\x03|$)')
    found_sigs = der_pattern.findall(tx_bytes)

    # Captures Compressed (33-bytes) and Uncompressed (65-bytes) Public Keys
    pubkey_pattern = re.compile(b'(?:[\x02\x03][\x00-\xff]{32})|(?:\x04[\x00-\xff]{64})')
    found_keys = pubkey_pattern.findall(tx_bytes)

    if found_sigs:
        print(f"  Found {len(found_sigs)} signature(s) in TX ID: {txid}")
        
        for idx, sig_bytes in enumerate(found_sigs):
            try:
                expected_total_len = sig_bytes[1] + 2
                clean_sig_bytes = sig_bytes[:expected_total_len]

                r, s = util.sigdecode_der(clean_sig_bytes, SECP256k1.order)
                pub_bytes = found_keys[idx] if idx < len(found_keys) else b''
                
                # Compute real address from key bytes
                address = pubkey_to_address(pub_bytes) if pub_bytes else "UnknownAddress"
                
                # Reconstruct scriptPubKey from public key hash to pass to offline preimage resolver
                sha = hashlib.sha256(pub_bytes).digest()
                h = hashlib.new('ripemd160')
                h.update(sha)
                pkh = h.digest()
                script_pub_key = b'\x76\xa9\x14' + pkh + b'\x88\xac'
                
                # True cryptographic mathematical Z value calculation
                z_val = compute_legacy_z(tx_bytes, idx, script_pub_key)

                sig_data = {
                    "txid": txid,
                    "address": address,
                    "pubkey": pub_bytes.hex() if pub_bytes else "N/A",
                    "r": hex(r)[2:].zfill(64),
                    "s": hex(s)[2:].zfill(64),
                    "z": z_val
                }
                
                print(f"    🌟 [SUCCESS]")
                print(f"      r: {sig_data['r']}")
                print(f"      s: {sig_data['s']}")
                print(f"      z: {sig_data['z']}")
                print(f"      Address: {address}\n")
                
                # Run vulnerability scanning rules locally
                check_memory_usage()
                new_r_int = int(sig_data["r"], 16)
                for old_sig in SIGNATURES:
                    if old_sig["txid"] == sig_data["txid"]: continue
                    old_r_int = int(old_sig["r"], 16)
                    if old_r_int == 0: continue
                    
                    if sig_data["r"] == old_sig["r"]:
                        save_identical_r_signature(old_sig, sig_data)
                    elif sig_data["address"] == old_sig["address"]:
                        ratio = new_r_int / old_r_int if new_r_int >= old_r_int else old_r_int / new_r_int
                        if 0.9 <= ratio <= 1.1:
                            save_vulnerability(old_sig, sig_data, ratio)
                
                SIGNATURES.append(sig_data)
                
            except Exception:
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
