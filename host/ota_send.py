import serial
import struct
import argparse
import time
import os

MAGIC = 0xABCD  # Magic number for frame header
VERSION = 1     # Protocol version
CMD_HELLO = 1
CMD_BEGIN = 2
CMD_DATA = 3
CMD_END = 4

OTA_MAGIC = b"OTAF"

ACK = b'\x06'  # Acknowledgment byte
NAK = b'\x15'  # Negative acknowledgment byte

def calculate_checksum(data):
    return sum(data) & 0xFF

def send_frame(ser, cmd, seq, payload=b""):
    header = struct.pack("<H B B H H", MAGIC, VERSION, cmd, seq, len(payload))
    frame_data = header + payload
    
    checksum = calculate_checksum(frame_data)
    frame = frame_data + struct.pack("<B", checksum)

    retry = 0
    while retry < 3:
        ser.reset_input_buffer()
        ser.write(frame)
        ser.flush()

        response = ser.read(1)
        if response == ACK:
            return True
        elif response == NAK:
            print(f"NAK received, retrying... ({retry + 1}/3)")
        elif not response:
            print(f"Timeout, retrying... ({retry + 1}/3)")
        else:
            print(f"Unexpected response: 0x{response.hex()}, retrying... ({retry + 1}/3)")
        retry += 1
        time.sleep(0.5)
    
    raise Exception("Failed to send frame after 3 retries")

def send_ota_package(port, baudrate, file_path):
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"OTA package file '{file_path}' not found.")
    
    with open(file_path, "rb") as f:
        ota_data = f.read()
    total_size = len(ota_data)

    # Verify OTA_MAGIC
    if total_size >= 120:
        magic, _, _, target_id, img_version = struct.unpack_from("<4s H H I I", ota_data, 0)
        
        if magic == OTA_MAGIC:
            print(f"OTA package target ID: {target_id}, image version: {img_version}")
        else:
            print("Warning: OTA package does not have the expected magic number.")
            return
    else:
        print("Warning: OTA package is too small to contain header information.")
        return

    print(f"{port} ({baudrate} bps) - Sending OTA package '{file_path}' ({total_size} bytes)")
    try:
        ser = serial.Serial(port, baudrate, timeout=2.0)
        time.sleep(0.1)
        ser.reset_input_buffer()
    except Exception as e:
        raise Exception(f"Failed to open serial port {port}: {e}")
    
    try:
        # 1. Send Hello command to check device readiness
        print("Checking device(Hello)...")
        send_frame(ser, CMD_HELLO, 0)

        # 2. Send Begin command with OTA package size
        print(f"Sending OTA package size: {total_size} bytes")
        size_payload = struct.pack("<I", total_size)
        send_frame(ser, CMD_BEGIN, 0, size_payload)

        chunk_size = 256
        seq = 0
        offset = 0
        
        # 3. Send OTA package data in chunks
        print("Sending OTA package data...")
        while offset < total_size:
            chunk = ota_data[offset:offset + chunk_size]
            send_frame(ser, CMD_DATA, seq, chunk)

            offset += len(chunk)
            seq += 1
            progress = (offset / total_size) * 100
            print(f"Progress: {progress:.2f}% ({offset}/{total_size} bytes)", end="\r")

        print()

        # 4. Send End command to finalize the OTA process
        print("Sending OTA package end...")
        send_frame(ser, CMD_END, seq)

        time.sleep(5) 

        while ser.in_waiting > 0:
            board_log = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
            print(board_log, end="")

        print("OTA package sent successfully.")
    except Exception as e:
        print(f"\nError during OTA package sending: {e}")
    finally:
        ser.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OTA Package Sender")
    parser.add_argument("--port", required=True, help="Serial port (e.g., COM3)")
    parser.add_argument("--baudrate", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--package", required=True, help="Path to the OTA package file")

    args = parser.parse_args()
    send_ota_package(args.port, args.baudrate, args.package)
