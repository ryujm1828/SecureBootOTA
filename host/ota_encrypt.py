import os
import argparse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# Master Key (32 bytes for AES-256)
MASTER_KEY = b"SecretCompanyMasterKey0123456789"  // 32bytes (256 bits)

# UID of the target device (12 bytes for example)
# EX: 0x00112233445566778899AABB
target_device_uid = bytes.fromhex("00112233445566778899AABB")

def generate_encrypted_firmware(input_bin_path, output_ota_path):
    # Generate an AES-CCM key for the target device using HKDF
    device_aes_key = HKDF(
        master=MASTER_KEY,
        key_len=32,
        salt=b"OTA_SALT",          # Salt for HKDF
        hashmod=SHA256,
        context=target_device_uid  # Use UID as context
    )
    print(f"[PC] Derived Device Key: {device_aes_key.hex()}")

    # Read the plaintext firmware binary
    with open(input_bin_path, "rb") as f:
        plaintext_firmware = f.read()

    # Generate a random nonce for AES-CCM (12 bytes recommended)
    nonce = os.urandom(12)

    # Encrypt the firmware using AES-CCM
    cipher = AES.new(device_aes_key, AES.MODE_CCM, nonce=nonce)
    ciphertext, mac_tag = cipher.encrypt_and_digest(plaintext_firmware)

    print(f"[PC] Encryption Done. Payload size: {len(ciphertext)} bytes")
    print(f"[PC] Nonce: {nonce.hex()}, MAC: {mac_tag.hex()}")

    # Write the encrypted firmware to the OTA package file
    with open(output_ota_path, "wb") as f:
        # [Nonce (12 bytes)] + [MAC Tag (16 bytes)] + [Ciphertext (variable length)]
        f.write(nonce)
        f.write(mac_tag)
        f.write(ciphertext)
        
    print("[PC] OTA Package Generated Successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt firmware binary for OTA update")
    parser.add_argument("--input", required=True, help="Path to the input firmware binary (.bin)")
    parser.add_argument("--output", required=True, help="Path to the output encrypted OTA package (.ota)")
    args = parser.parse_args()
    generate_encrypted_firmware(args.input, args.output)