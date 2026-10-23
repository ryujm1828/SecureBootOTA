import ecdsa
import argparse
import os

def extract_public_key(pem_file):
    if not os.path.exists(pem_file):
        print(f"[-] File not found: {pem_file}")
        return

    try:
        with open(pem_file, "rb") as f:
            sk = ecdsa.SigningKey.from_pem(f.read())
        
        # extract the verifying key (public key) from the signing key
        vk = sk.get_verifying_key()
        
        # convert the public key to bytes
        pubkey_bytes = vk.to_string()
        
        print(f"[*] '{pem_file}'에서 공개키 추출 성공!")
        print(f"[*] 키 길이: {len(pubkey_bytes)} bytes\n")
        
        # print the public key in C array format
        c_array = ", ".join([f"0x{b:02x}" for b in pubkey_bytes])
        
        # format the output for better readability
        formatted_array = ""
        for i in range(0, len(pubkey_bytes), 16):
            chunk = pubkey_bytes[i:i+16]
            formatted_array += "    " + ", ".join([f"0x{b:02x}" for b in chunk]) + ",\n"
            
        print("/* === copy and paste the following code into the bootloader main.c === */")
        print("const uint8_t ecdsa_public_key[64] = {")
        print(formatted_array.rstrip(',\n')) # rstrip to remove the last comma and newline
        print("};")
        print("/* ========================================================== */")
        
    except Exception as e:
        print(f"[-] Error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract C-array Public Key from PEM")
    parser.add_argument("--key", required=True, help="Path to the PEM file containing the ECDSA private key")
    
    args = parser.parse_args()
    extract_public_key(args.key)