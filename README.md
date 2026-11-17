# SecureBootOTA
STM32F411RE 기반 보안 OTA 부트로더 - ECDSA 서명 검증, AES-256-CCM 암호화, 롤백 방어 구현

## 주요 기능
- ECDSA P-256 서명 기반 펌웨어 무결성 검증
- HKDF(SHA-256) + 디바이스 UID 기반 디바이스별 AES-256 키 파생
- AES-256-CCM 암호화 OTA 패키지 전송 및 복호화
- A/B 슬롯 기반 롤백 방어
- IWDG 워치독 기반 부트루프 감지 및 자동 복구

## 통신 흐름
1. 앱 패키지 생성: `ota_pack.py` - SHA-256 계산, OTA 헤더 조립, ECDSA P-256 서명 → `.ota` 파일
2. 앱 패키지 암호화: `ota_encrypt.py` - HKDF 키 파생, AES-256-CCM 암호화 → `.bin` 파일
3. 앱 패키지 전송: `ota_send.py` - UART 115200bps 커스텀 프로토콜로 MCU에 전송
4. OTA 수신 및 외부 Flash 저장: A/B 슬롯 중 비활성 슬롯에 암호화 상태로 저장
5. 펌웨어 검증: 헤더 복호화 → 헤더 필드/버전/ECDSA 검증 → 전체 복호화하며 MAC·SHA-256 검증
6. 설치: 검증 통과 시 SRAM 버퍼에서 복호화하여 내부 Flash에 직접 기록, 실패 시 이전 슬롯으로 롤백
7. 앱 점프: VTOR 재설정 후 앱의 Reset Handler로 점프

## 메모리 맵
### W25Q64 (외부 Flash, 8MB)
| 영역   | 주소     | 크기 | 용도 |
| ------ | -------- | ---- | ---- |
| Slot A | 0x000000 | 1MB  | 암호화된 OTA 패키지 슬롯 A |
| Slot B | 0x100000 | 1MB  | 암호화된 OTA 패키지 슬롯 B |

두 슬롯을 번갈아 사용하며, 비활성 슬롯에 신규 패키지를 저장해 롤백에 활용합니다.

### 내부 Flash (STM32F411RE, 512KB)
| 영역        | 주소       | 크기              | 용도 |
| ----------- | ---------- | ----------------- | ---- |
| Bootloader  | 0x08000000 | Sector 0~3 (64KB) | 부트로더 |
| OTA Header  | 0x08010000 | 512B              | 현재 설치된 펌웨어의 OTA 헤더 |
| Application | 0x08010200 | Sector 4~7 (448KB)| 애플리케이션 |

## 펌웨어 검증 (5단계)
1. OTA 헤더 필드 검증 - Magic(`OTAF`), Version, HeaderSize, TargetID(`0x0411`), ImageSize 범위
2. 안티 롤백 - 신규 버전이 현재 설치 버전 이상인지 확인 (롤백 복원 시에는 생략)
3. ECDSA P-256 서명 검증 - 헤더 56B의 SHA-256 해시에 대한 서명 검증
4. AES-CCM MAC 태그 검증 - 전체 암호문의 CBC-MAC과 수신 MAC 비교 (Constant-time)
5. SHA-256 페이로드 해시 검증 - 복호화된 앱 바이너리 해시와 헤더 내 해시 비교 (Constant-time)

## 발견된 취약점 및 해결
[세부 취약점 보고서](/docs/취약점%20보고서/취약점_보고서.md)

### 취약점 재현 (CWE-312, CWE-319)
- 기존 설계에서 복호화된 펌웨어가 외부 Flash에 평문으로 저장됨
- USB 로직 분석기로 SPI 버스를 도청해 펌웨어 전체 추출 성공 확인 (복호화된 펌웨어를 평문으로 읽어올 때 도청됨)

### 패치
- 외부 Flash에는 암호화된 패키지만 저장 (평문 저장소 완전 제거)
- 복호화는 SRAM 버퍼에서만 수행 후 즉시 내부 Flash에 기록

## 사용 기술 스택
| 분류       | 내용 |
| ---------- | ---- |
| MCU        | STM32F411RE (ARM Cortex-M4, 84MHz, 512KB Flash) |
| 개발환경   | STM32CubeIDE 2.2.0, STM32CubeMX 6.18.1 |
| 암호화     | AES-256-CCM, ECDSA P-256 (uECC), SHA-256, HKDF (RFC 5869) |
| 외부 메모리| W25Q64 SPI NOR Flash (8MB) |
| 통신       | UART 115200bps (커스텀 바이너리 프로토콜) |
| 호스트 도구| Python (cryptography, pycryptodome, pyserial) |
| 코딩 표준  | MISRA-C 2012 (cppcheck 검증, 현재 리팩토링 중) |

## 패키지 생성 및 업데이트 방법
### 1. OTA 패키지 생성 (서명)
```bash
python host/ota_pack.py --input firmware/testapp/Debug/TestApp.bin --output host/app_v1.ota --version 1 --key keys/test_privkey.pem
```
### 2. AES-256-CCM 암호화
```bash
python host/ota_encrypt.py --input host/app_v1.ota --output host/app_v1_enc.bin
```
### 3. UART 전송 (보드의 B1 버튼을 누른 상태에서 Reset 혹은 전원 켜기)
```bash
python host/ota_send.py --port COM5 --package host/app_v1_enc.bin
```

## 배포 시 주의사항
### 키 교체
이 저장소의 `keys/test_privkey.pem`과 펌웨어에 하드코딩된 키는 테스트용 샘플이므로, 실제 배포 시 아래 내용을 모두 교체해야 함

- `keys/test_privkey.pem`: ECDSA 개인키 (서명용, PC 보관)
- `firmware/bootloader/Core/Src/boot_keys.c`: `ecdsa_public_key[64]`(ECDSA 공개키)  `MASTER_KEY[32]` (MASTER_KEY)
- `firmware/bootloader/Core/Inc/boot_config.h`: USE_REAL_DEVICE_UID (1로 설정해야 실제 기기의 UID 사용)
- `host/ota_encrypt.py`: MASTER_KEY, target_device_uid(실제 기기 uid)

공개키는 개인키에서 `host/extract_pubkey.py`로 추출해 `boot_keys.c`에 반영

### RDP (Read Out Protection) 설정
- 현재 RDP Level 0으로 설정되어 있음
- 실제 배포 시에는 STM32CubeProgrammer에서 RDP Level 2로 설정해야 펌웨어 평문 유출을 막을 수 있음

## 사용한 오픈소스 코드
- [B-Con/crypto-algorithms](https://github.com/B-Con/crypto-algorithms) - SHA-256, AES 구현
- [kmackay/micro-ecc](https://github.com/kmackay/micro-ecc) - uECC (ECDSA P-256)