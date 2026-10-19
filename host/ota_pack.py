import argparse
import struct
import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization

MAGIC = b"OTAF"
FORMAT_VERSION = 1
HEADER_SIZE = 120
HASH_ALG = 1 # 1=SHA-256
SIGN_ALG = 1 # 1=ECDSA

def generate_key(key_path):
    print("Generating ECDSA key pair")
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_path, 'wb') as f:
        f.write(pem_private)
    print(f"Private key saved to {key_path}")

def load_private_key(key_path):
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def create_ota_package(input_file, output_file, image_version, target_id, key_path):
    #Read payload and calculate its SHA-256 hash
    with open(input_file, 'rb') as f:
        payload = f.read()
    
    image_size = len(payload)
    payload_sha256 = hashlib.sha256(payload).digest()

    # Create header (56 bytes)
    # 4s(magic) + H(Format version) + H(Hedaer size) + I(Target ID) + I(Image version) + I(Image size) + B(Hash algorithm) + B(Signature algorithm) + 2s(Reserved) + 32(Hash)
    header_format = '<4s H H I I I B B 2s 32s'
    reserved = b'\x00\x00'

    unsigned_header = struct.pack(
        header_format,
        MAGIC,
        FORMAT_VERSION,
        HEADER_SIZE,
        target_id,
        image_version,
        image_size,
        HASH_ALG,
        SIGN_ALG,
        reserved,
        payload_sha256
    )

    # Create ECDSA signature
    if SIGN_ALG == 1:
        private_key = load_private_key(key_path)
        der_signature = private_key.sign(unsigned_header, ec.ECDSA(hashes.SHA256()))

        # Sign with DER format and then convert to raw r,s format, serialized to 64 bytes
        r, s = decode_dss_signature(der_signature)
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        raw_signature = r_bytes + s_bytes
        
        final_header = unsigned_header + raw_signature
        if len(final_header) != HEADER_SIZE:
            raise ValueError("Header size error: expected {}, got {}".format(HEADER_SIZE, len(final_header)))

    else:
        raise ValueError("Unsupported signature algorithm")
    
    # Save OTA package
    with open(output_file,'wb') as f:
        f.write(final_header)
        f.write(payload)
    
    print(f"OTA package created: {output_file}")
    print(f"Image version: {image_version}, Target ID: {target_id}, Image size: {image_size} bytes")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OTA Package Creator")
    parser.add_argument("--input", required=True, help="Path to input binary file (.bin)")
    parser.add_argument("--output", required=True, help="Path to output OTA package file (.ota)")
    parser.add_argument("--version", type=int, required=True, help="Image version (integer)")
    parser.add_argument("--target", type=int, required=False, default=0x0411, help="Target ID (integer)") #Default: STM32F411RE
    parser.add_argument("--key", required=True, help="Path to ECDSA private key file (.pem)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Input file {args.input} does not exist.")
        exit(1)
    
    if not os.path.exists(args.key):
        print(f"Key file {args.key} does not exist. Generating a new key.")
        generate_key(args.key)
    
    create_ota_package(args.input, args.output, args.version, args.target, args.key)