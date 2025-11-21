import sys
import os

# src 경로 설정
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from ntag424_python.ntag424 import NTAG424

def main():
    print("=== NTAG 424 DNA 최종 설정 (LSB Fix) ===")
    
    tag = NTAG424()
    if not tag.connect() or not tag.select_app():
        print("❌ 연결 실패")
        return

    # 1. 인증 (Key 0)
    if not tag.authenticate_ev2_first(key_no=0):
        print("❌ 인증 실패")
        tag.disconnect()
        return
    print("✅ 인증 성공")

    # 2. URL 구조 정의
    # ?e= 뒤에 32글자(16바이트 암호화 데이터의 HEX 문자열)가 들어감
    base_url = "https://ntag.nxp.com/424?e="
    picc_data_len = 32
    cmac_str = "&c="
    
    # 3. 오프셋 계산
    picc_data_offset = len(base_url)
    cmac_offset = picc_data_offset + picc_data_len + len(cmac_str)
    
    print(f"📍 오프셋: PICCData={picc_data_offset}, CMAC={cmac_offset}")

    # 4. ChangeFileSettings 파라미터 조립
    
    # (1) File Access Rights (2 bytes)
    # 목표: Read=E, Write=0, RW=0, Change=0 -> 0xE000
    # LSB First 전송: [00, E0]
    # bytes.fromhex("00E0")을 쓰면 [00, E0]가 됩니다. (이건 맞음)
    file_access = bytes.fromhex("00E0")

    # (2) SDM Options (1 byte)
    # UID(1)|Ctr(1)|Limit(0)|Enc(0)|RFU(0)|ASCII(1) -> 0xC1
    sdm_opts = bytes([0xC1])

    # (3) SDM Access Rights (2 bytes) - [여기가 문제였음!!]
    # 목표: Meta=0(암호화), File=0(MAC), RFU=F, Ctr=0 -> 0x00F0
    # LSB First 전송: [F0, 00] 순서로 보내야 함.
    # bytes.fromhex("00F0") -> [00, F0] -> 태그는 F000(Meta=F, Disable)로 인식 -> 에러
    # bytes.fromhex("F000") -> [F0, 00] -> 태그는 00F0(Meta=0, Enable)로 인식 -> 성공
    sdm_access = bytes.fromhex("F000") 

    # (4) 오프셋 데이터 (총 12 bytes)
    change_params = (
        sdm_opts +                                  # 1 byte
        sdm_access +                                # 2 bytes (LSB Fixed)
        picc_data_offset.to_bytes(3, 'little') +    # 3 bytes
        bytes.fromhex("000000") +                   # 3 bytes (MAC Input Offset)
        cmac_offset.to_bytes(3, 'little')           # 3 bytes (MAC Offset)
    )

    print(f"🚀 전송 파라미터(Hex): {change_params.hex()}")
    print("🚀 설정 변경 요청 중...")
    
    if tag.change_file_settings(2, file_access, change_params):
        print("✅ 설정 변경 성공!")
    else:
        print("❌ 설정 변경 실패")
        tag.disconnect()
        return

    # 5. NDEF 데이터 쓰기
    url_template = f"{base_url}{'0'*32}{cmac_str}{'0'*16}"
    url_bytes = url_template.encode('ascii')
    
    # NDEF Header: D1 (Short Record) | 01 (Type Len) | Payload Len | 55 (URI) | 00 (No Prefix)
    ndef_header = bytes([0xD1, 0x01, len(url_bytes) + 1, 0x55, 0x00]) + url_bytes
    tlv_data = bytes([0x03, len(ndef_header)]) + ndef_header + bytes([0xFE])

    print("✍️ NDEF 데이터 쓰기 중...")
    if tag.write_data(2, tlv_data):
        print(f"🎉 성공! 태그 URL: {url_template}")
    else:
        print("❌ 데이터 쓰기 실패")

    tag.disconnect()

if __name__ == "__main__":
    main()