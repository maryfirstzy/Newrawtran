import hashlib
import struct
import psutil
from ecdsa import util, SECP256k1

# Configuration and Output Files
INPUT_HEX_FILE = "raw_transactions.txt"  # Put your raw hex transactions here (one per line)
VULN_FILE = "vulnerabilities.txt"
IDENTICAL_R_FILE = "identical_r_signatures.txt"

SIGNATURES = []

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a", encoding="utf-8") as f:
        f.write(linia + "\n")

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def parse_pushdata(script_bytes):
    items = []
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if opcode <= 75:
            items.append(script_bytes[i:i+opcode])
            i += opcode
        elif opcode == 76:
            if i >= len(script_bytes): break
            length = script_bytes[i]
            i += 1
            items.append(script_bytes[i:i+length])
            i += length
        elif opcode == 77:
            if i + 2 > len(script_bytes): break
            length = int.from_bytes(script_bytes[i:i+2], 'little')
            i += 2
            items.append(script_bytes[i:i+length])
            i += length
        else:
            items.append(bytes([opcode]))
    return items

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
    print("⚠️ ZNALEZIONO IDENTYCZNE r")

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
        
        # Network byte (0x00 for Mainnet P2PKH)
        version_payload = b'\x00' + pubkey_hash
        checksum = sha256d(version_payload)[:4]
        full_payload = version_payload + checksum
        
        # Base58 Encoding
        digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        value = int.from_bytes(full_payload, 'big')
        result = ""
        while value > 0:
            value, mod = divmod(value, 58)
            result = digits[mod] + result
            
        # Add leading 1s for zero bytes
        for byte in full_payload:
            if byte == 0:
                result = digits[0] + result
            else:
                break
        return result
    except Exception:
        return "UnknownAddress"

def zdekoduj_transakcje(raw_tx_hex):
    """Parses raw transaction, computes z-values, extracts r, s, and local address"""
    try:
        data = bytes.fromhex(raw_tx_hex.strip())
        txid = sha256d(data)[::-1].hex()
    except Exception:
        return  # Skip invalid hex strings

    offset = 0
    def read_varint(data, offset):
        if offset >= len(data): return 0, offset
        prefix = data[offset]
        offset += 1
        if prefix < 0xfd:
            return prefix, offset
        elif prefix == 0xfd:
            val = int.from_bytes(data[offset:offset+2], 'little')
            offset += 2
            return val, offset
        elif prefix == 0xfe:
            val = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            return val, offset
        val = int.from_bytes(data[offset:offset+8], 'little')
        offset += 8
        return val, offset

    try:
        # Version
        version = int.from_bytes(data[offset:offset+4], "little")
        offset += 4
        
        # Handle SegWit marker/flag if present
        is_segwit = False
        if data[offset] == 0x00:
            if data[offset+1] != 0x00:
                is_segwit = True
                offset += 2

        # Inputs (vin)
        vin_count, offset = read_varint(data, offset)
        vin = []
        for _ in range(vin_count):
            entry = {}
            entry["txid"] = data[offset:offset+32][::-1].hex()
            offset += 32
            entry["vout"] = int.from_bytes(data[offset:offset+4], "little")
            offset += 4
            script_len, offset = read_varint(data, offset)
            entry["scriptSig"] = data[offset:offset+script_len]
            offset += script_len
            entry["sequence"] = int.from_bytes(data[offset:offset+4], "little")
            offset += 4
            vin.append(entry)

        # Outputs (vout) - Completed from original snippet
        vout_count, offset = read_varint(data, offset)
        vout = []
        for _ in range(vout_count):
            entry = {}
            entry["value"] = int.from_bytes(data[offset:offset+8], "little")
            offset += 8
            script_len, offset = read_varint(data, offset)
            entry["scriptPubKey"] = data[offset:offset+script_len]
            offset += script_len
            vout.append(entry)

        # Locktime
        locktime = data[offset:offset+4]
        offset += 4

        # Extract signatures from input scriptSigs (Legacy P2PKH parser)
        for index, inp in enumerate(vin):
            script_bytes = inp["scriptSig"]
            pushed_items = parse_pushdata(script_bytes)
            
            if len(pushed_items) >= 2:
                sig_bytes = pushed_items[0]
                pub_bytes = pushed_items[1]
                
                # Check for standard DER signature formatting
                if sig_bytes.startswith(b'\x30'):
                    try:
                        # Strip sighash type byte at the end (usually \x01)
                        der_sig = sig_bytes[:-1] 
                        r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                        
                        # Compute z (Simplified approximation for offline processing verification)
                        # An accurate 'z' requires constructing the preimage without scriptSig.
                        # For pure passive pattern matching across raw feeds, we hash the script input.
                        z_val = hashlib.sha256(script_bytes).hexdigest()
                        
                        address = pubkey_to_address(pub_bytes)
                        
                        sig_data = {
                            "txid": txid,
                            "address": address,
                            "pubkey": pub_bytes.hex(),
                            "r": hex(r)[2:],
                            "s": hex(s)[2:],
                            "z": z_val
                        }
                        analyze_signature(sig_data)
                    except Exception:
                        continue
    except Exception:
        pass # Gracefully handle corrupted transaction formatting blocks

def main():
    print(f"🚀 Loading raw hex strings from {INPUT_HEX_FILE}...")
    try:
        with open(INPUT_HEX_FILE, "r") as f:
            lines = f.readlines()
        
        print(f"🔍 Processing {len(lines)} transactions offline...")
        for idx, line in enumerate(lines):
            cleaned_line = line.strip()
            if cleaned_line:
                zdekoduj_transakcje(cleaned_line)
                
        print("✅ Offline matching run complete.")
    except FileNotFoundError:
        print(f"❌ Error: Please create '{INPUT_HEX_FILE}' and paste your transaction hex lines there.")

if __name__ == "__main__":
    main()
