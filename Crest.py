import hashlib
import struct
import psutil
import re
import math
from ecdsa import util, SECP256k1
from concurrent.futures import ProcessPoolExecutor, as_completed

# Configuration and Output Files
INPUT_HEX_FILE = "raw_transactions.txt"
VULN_FILE = "vulnerabilities.txt"
IDENTICAL_R_FILE = "identical_r_signatures.txt"

# Signature database cache for single-threaded processing / analytics merge
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
    digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(payload, 'big')
    result = ""
    while value > 0:
        value, mod = divmod(value, 58)
        result = digits[mod] + result
    for byte in payload:
        if byte == 0:
            result = digits[0] + result
        else:
            break
    return result

def pubkey_to_address(pubkey_bytes):
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
    try:
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

        preimage = struct.pack("<I", 1) 
        preimage += struct.pack("B", vin_count)
        for i, inp in enumerate(inputs_data):
            preimage += inp['txid'] + inp['vout']
            if i == input_index:
                preimage += struct.pack("B", len(script_pub_key)) + script_pub_key
            else:
                preimage += b'\x00'
            preimage += inp['seq']

        vout_count, offset = read_varint(raw_tx_bytes, offset)
        preimage += struct.pack("B", vout_count)
        for _ in range(vout_count):
            preimage += raw_tx_bytes[offset:offset+8]
            offset += 8
            slen, offset = read_varint(raw_tx_bytes, offset)
            preimage += struct.pack("B", slen) + raw_tx_bytes[offset:offset+slen]
            offset += slen
            
        preimage += raw_tx_bytes[offset:offset+4]
        preimage += struct.pack("<I", 1)
        return sha256d(preimage).hex()
    except Exception:
        return "ErrorComputingZ"

def extract_sigs_worker(raw_tx_hex):
    """Worker function designed for isolated parallel CPU processing."""
    extracted = []
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex.strip())
        txid = sha256d(tx_bytes)[::-1].hex()
    except Exception:
        return extracted

    der_pattern = re.compile(b'\x30[\x44-\x49]\x02[\x1f-\x21].*?\x02[\x1f-\x21].*?(?=\x01|\x02|\x03|$)')
    found_sigs = der_pattern.findall(tx_bytes)
    pubkey_pattern = re.compile(b'(?:[\x02\x03][\x00-\xff]{32})|(?:\x04[\x00-\xff]{64})')
    found_keys = pubkey_pattern.findall(tx_bytes)

    for idx, sig_bytes in enumerate(found_sigs):
        try:
            expected_total_len = sig_bytes[1] + 2
            clean_sig_bytes = sig_bytes[:expected_total_len]
            r, s = util.sigdecode_der(clean_sig_bytes, SECP256k1.order)
            pub_bytes = found_keys[idx] if idx < len(found_keys) else b''
            
            address = pubkey_to_address(pub_bytes) if pub_bytes else "UnknownAddress"
            
            sha = hashlib.sha256(pub_bytes).digest()
            h = hashlib.new('ripemd160')
            h.update(sha)
            script_pub_key = b'\x76\xa9\x14' + h.digest() + b'\x88\xac'
            z_val = compute_legacy_z(tx_bytes, idx, script_pub_key)

            extracted.append({
                "txid": txid,
                "address": address,
                "pubkey": pub_bytes.hex() if pub_bytes else "N/A",
                "r": hex(r)[2:].zfill(64),
                "s": hex(s)[2:].zfill(64),
                "z": z_val
            })
        except Exception:
            continue
    return extracted

def analyze_all_signatures(sig_list):
    """Processes collected structural signatures for patterns and mathematical variance."""
    global SIGNATURES
    for sig_data in sig_list:
        check_memory_usage()
        new_r_int = int(sig_data["r"], 16)
        
        for old_sig in SIGNATURES:
            if old_sig["txid"] == sig_data["txid"]: 
                continue
                
            old_r_int = int(old_sig["r"], 16)
            if old_r_int == 0: 
                continue
            
            # 1. Exact Structural Match Scan
            if sig_data["r"] == old_sig["r"]:
                line = (
                    f"txid1: {old_sig['txid']}\naddress1: {old_sig['address']}\n"
                    f"r: {old_sig['r']}\ns1: {old_sig['s']}\nz1: {old_sig['z']}\n"
                    f"txid2: {sig_data['txid']}\naddress2: {sig_data['address']}\n"
                    f"r: {sig_data['r']}\ns2: {sig_data['s']}\nz2: {sig_data['z']}\n"
                    "----------------------------------"
                )
                zapisz_do_pliku(IDENTICAL_R_FILE, line)
                print(f"⚠️ MATCH: Identical r parameters caught in TX: {sig_data['txid']}")
            
            # 2. Mathematical Ratio Proximity Scan (For the same address)
            elif sig_data["address"] == old_sig["address"]:
                ratio = new_r_int / old_r_int if new_r_int >= old_r_int else old_r_int / new_r_int
                if 0.9 <= ratio <= 1.1:
                    line = (
                        f"txid1: {old_sig['txid']}\naddress: {old_sig['address']}\n"
                        f"r1: {old_sig['r']}\ns1: {old_sig['s']}\nz1: {old_sig['z']}\n"
                        f"txid2: {sig_data['txid']}\naddress2: {sig_data['address']}\n"
                        f"r2: {sig_data['r']}\ns2: {sig_data['s']}\nz2: {sig_data['z']}\n"
                        f"Ratio: {ratio:.6f}\n"
                        "----------------------------------"
                    )
                    zapisz_do_pliku(VULN_FILE, line)
                    print(f"🚨 ALERT: Mathematical r-ratio variance found ({ratio:.4f}) on {sig_data['address']}")
                    
        SIGNATURES.append(sig_data)

def main():
    print(f"🚀 Initializing high-speed parallel parsing engine...")
    try:
        with open(INPUT_HEX_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        print(f"🔍 Distributing {len(lines)} hex inputs across available CPU threads...")
        
        all_extracted_signatures = []
        # Multi-core process mapper allows non-blocking execution across cores
        with ProcessPoolExecutor() as executor:
            futures = {executor.submit(extract_sigs_worker, line): line for line in lines}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_extracted_signatures.extend(result)
                    
        print(f"📊 Extracted {len(all_extracted_signatures)} signatures total. Evaluating relationships...")
        analyze_all_signatures(all_extracted_signatures)
        print("✅ Analysis loop finished.")
        
    except FileNotFoundError:
        print(f"❌ Target context file '{INPUT_HEX_FILE}' not found.")

if __name__ == "__main__":
    main()
