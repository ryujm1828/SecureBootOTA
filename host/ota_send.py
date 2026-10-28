import serial
import struct
import argparse
import time
import os

MAGIC = 0xABCD  # Frame header magic
VERSION = 1     # Protocol version
CMD_HELLO = 1
CMD_BEGIN = 2
CMD_DATA = 3
CMD_END = 4

OTA_MAGIC = b"OTAF"

ACK = b'\x06'  # Acknowledgment
NAK = b'\x15'  # Negative acknowledgment

def calculate_checksum(data):
    return sum(data) & 0xFF

def send_frame(ser, cmd, seq, payload=b""):
    header = struct.pack("<H B B H H", MAGIC, VERSION, cmd, seq, len(payload))
    frame_data = header + payload
    
    checksum = calculate_checksum(frame_data)
    frame = frame_data + struct.pack("<B", checksum)

    # Longer timeout for CMD_END due to decryption and flash erase
    timeout = 15.0 if cmd == CMD_END else 3.0
    retry = 0

    while retry < 3:
        ser.reset_input_buffer()
        ser.write(frame)
        ser.flush()

        start_time = time.time()
        while (time.time() - start_time) < timeout:
            if ser.in_waiting > 0:
                b = ser.read(1)
                if b == ACK:
                    return True
                elif b == NAK:
                    print(f"\nNAK received, retrying... ({retry + 1}/3)")
                    break
                else:
                    # Print debug log from board
                    try:
                        print(b.decode('utf-8', errors='ignore'), end="", flush=True)
                    except Exception:
                        pass
            else:
                time.sleep(0.01)
        else:
            print(f"\nTimeout waiting for response, retrying... ({retry + 1}/3)")

        retry += 1
        time.sleep(0.5)
    
    raise Exception(f"Failed to send frame (cmd={cmd}) after 3 retries")

def send_ota_package(port, baudrate, file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"OTA package file '{file_path}' not found.")
    
    with open(file_path, "rb") as f:
        ota_data = f.read()
    total_size = len(ota_data)

    if total_size < 120:
        print("Warning: OTA package is too small.")
        return

    # Check package format
    magic, _, _, target_id, img_version = struct.unpack_from("<4s H H I I", ota_data, 0)
    if magic == OTA_MAGIC:
        print(f"Plain OTA package detected (Target ID: 0x{target_id:04X}, Version: {img_version})")
    else:
        print("Encrypted OTA package detected (Header check bypassed).")

    print(f"{port} ({baudrate} bps) - Sending OTA package '{file_path}' ({total_size} bytes)")
    try:
        ser = serial.Serial(port, baudrate, timeout=2.0)
        time.sleep(0.1)
        ser.reset_input_buffer()
    except Exception as e:
        raise Exception(f"Failed to open serial port {port}: {e}")
    
    try:
        # 1. Hello command
        print("Checking device(Hello)...")
        send_frame(ser, CMD_HELLO, 0)

        # 2. Begin command with total size
        print(f"Sending OTA package size: {total_size} bytes")
        size_payload = struct.pack("<I", total_size)
        send_frame(ser, CMD_BEGIN, 0, size_payload)

        chunk_size = 256
        seq = 0
        offset = 0
        
        # 3. Data command in chunks
        print("Sending OTA package data...")
        while offset < total_size:
            chunk = ota_data[offset:offset + chunk_size]
            send_frame(ser, CMD_DATA, seq, chunk)

            offset += len(chunk)
            seq += 1
            progress = (offset / total_size) * 100
            print(f"Progress: {progress:.2f}% ({offset}/{total_size} bytes)", end="\r")

        print()

        # 4. End command
        print("Sending OTA package end...")
        send_frame(ser, CMD_END, seq)

        # Read remaining board logs
        time.sleep(1)
        while ser.in_waiting > 0:
            board_log = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
            print(board_log, end="", flush=True)

        print("\nOTA package sent successfully.")
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
