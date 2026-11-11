import hashlib

with open("hacked_firmware", "rb") as f:
    raw = f.read()
cleaned = bytearray()
cleaned += raw[:120]  
pos = 120
while pos < len(raw):
    pos += 4         
    chunk = raw[pos : pos + 256]
    cleaned += chunk 
    pos += len(chunk)
with open("hacked_app_v2.ota", "wb") as f:
    f.write(cleaned)

hash_extracted = hashlib.sha256(cleaned).hexdigest()
with open("host/app_v2.ota", "rb") as f:
    hash_original = hashlib.sha256(f.read()).hexdigest()

print(f"추출 파일 해시: {hash_extracted}")
print(f"원본 파일 해시: {hash_original}")
if hash_extracted == hash_original:
    print("해시값이 일치합니다.")
else:
    print("해시값이 일치하지 않습니다.")