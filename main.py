import time
import sys
from ntag424 import NTAG424
from key_manager import get_derived_key, MASTER_KEYS

# 공장 초기화 키
FACTORY_KEY = bytes(16)

def calculate_offsets(base_url):
    """
    URL 길이와 NDEF 헤더를 고려하여 암호화 데이터가 들어갈 위치(Offset)를 계산합니다.
    """
    # 1. 구분자 결정 (? 또는 &)
    separator = "&" if "?" in base_url else "?"
    
    # 2. NDEF 파일 구조 (Type 4 Tag 표준)
    # [File Length (2bytes)] + [NDEF Header (5bytes)] + [Payload (URL...)]
    # - File Length: 전체 NDEF 메시지의 길이 (Big Endian)
    # - NDEF Header: D1(Record) + 01(TypeLen) + PLen(PayloadLen) + 55(URI) + 00(NoPrefix)
    # 따라서 실제 URL 데이터는 파일의 7번째 바이트(인덱스 7)부터 시작됩니다.
    file_header_len = 2
    record_header_len = 5
    total_header_len = file_header_len + record_header_len # 총 7바이트
    
    # 3. PICC Data Offset (암호화 데이터 위치)
    # [헤더 7바이트] + [URL] + [? 또는 &] + [enc=]
    # "enc=" 는 4글자
    enc_param = "enc="
    cmac_param = "&cmac="
    
    picc_data_offset = total_header_len + len(base_url) + len(separator) + len(enc_param)
    
    # 4. CMAC Offset (인증 코드 위치)
    # picc_data_offset + 암호화데이터(32) + "&cmac=" 길이
    cmac_offset = picc_data_offset + 32 + len(cmac_param)
    
    # 5. 최종 URL 템플릿 생성
    full_url = f"{base_url}{separator}{enc_param}{'0'*32}{cmac_param}{'0'*16}"
    
    return full_url, picc_data_offset, cmac_offset

def main():
    print("\n=== NTAG 424 DNA 설정 도구 (WalkD Ver.) ===")
    print("👉 태그를 리더기에 올려주세요. (Ctrl+C로 종료)")

    # 설정할 URL 정보
    target_url = "https://challenge.walkd.co.kr/dashboard"

    while True:
        try:
            tag = NTAG424()
            
            # 1. 연결 시도 (태그 없으면 재시도)
            if not tag.connect():
                # 리더기는 있지만 태그가 없는 경우를 위해 잠시 대기
                time.sleep(0.2)
                continue
            
            if not tag.select_app():
                # 태그는 있는데 NTAG 424가 아닌 경우
                tag.disconnect()
                time.sleep(0.2)
                continue

            print("\n⚡ 태그 감지됨! 설정 시작...")

            # 2. 인증 (Key 0)
            # 여기서는 편의상 공장 키(00..00)로 시도합니다. 
            # (이미 키가 변경된 태그라면 get_derived_key를 사용하도록 수정 필요)
            if not tag.authenticate_ev2_first(key_no=0, key=FACTORY_KEY):
                print("❌ 인증 실패 (Key 0 불일치)")
                print("   (이미 설정된 태그라면 키가 변경되었을 수 있습니다)")
                tag.disconnect()
                time.sleep(2)
                continue
                
            # 3. 오프셋 및 URL 계산
            full_url, picc_offset, cmac_offset = calculate_offsets(target_url)
            print(f"   ℹ️ 목표 URL: {full_url}")
            print(f"   📍 계산된 오프셋: Enc={picc_offset}, CMAC={cmac_offset}")

            # 4. 파일 설정 변경 (ChangeFileSettings)
            # 권한: Read=Free(E), Write=Key0(0) -> 00E0
            file_access = bytes.fromhex("00E0")
            
            # SDM 옵션: UID Mirror(Bit7)=1 | ReadCtr Mirror(Bit6)=1 | ASCII(Bit0)=1 -> C1
            sdm_opts = bytes([0xC1])
            
            # SDM 권한: MetaRead=Key2(2), FileRead=Key1(1), CtrRet=Key1(1)
            # Hex F121 -> LSB 전송 [F1, 21]
            sdm_access = bytes.fromhex("F121")

            change_params = (
                sdm_opts +
                sdm_access +
                picc_offset.to_bytes(3, 'little') +
                bytes.fromhex("000000") +
                cmac_offset.to_bytes(3, 'little')
            )

            if not tag.change_file_settings(2, file_access, change_params):
                print("❌ 파일 설정 변경 실패")
                tag.disconnect()
                continue

            # 5. NDEF 데이터 쓰기 (Type 4 Tag 표준 포맷) [중요]
            # 구조: [Length(2)] + [Header(5)] + https://en.wikipedia.org/wiki/String
            
            url_bytes = full_url.encode('ascii')
            
            # NDEF 레코드 헤더 (5바이트)
            # D1: Record Start/End, Well-Known Type
            # 01: Type Length (1)
            # Payload Length: URL길이 + 1 (Prefix 0x00 포함)
            # 55: Type 'U' (URI)
            # 00: ID Code (None)
            payload_len = len(url_bytes) + 1
            ndef_record_header = bytes([0xD1, 0x01, payload_len, 0x55, 0x00])
            
            # 전체 메시지 (헤더 + 데이터)
            ndef_message = ndef_record_header + url_bytes
            
            # 파일에 쓸 데이터: 맨 앞에 2바이트 길이(Big Endian) 추가
            total_len = len(ndef_message)
            file_data = total_len.to_bytes(2, 'big') + ndef_message

            print("✍️ NDEF 데이터 쓰는 중...")
            if tag.write_data_plain(2, file_data):
                print(f"✅ [성공] 설정 완료!")
                print(f"👉 핸드폰을 태그하여 확인해보세요.")
                print(f"   예상 URL: {target_url}?enc=...&cmac=...")
            else:
                print("❌ 데이터 쓰기 실패")

            tag.disconnect()
            print("💤 3초간 대기 (태그를 떼주세요)...")
            time.sleep(3)

        except KeyboardInterrupt:
            print("\n종료합니다.")
            break
        except Exception as e:
            # 연결 오류 등은 무시하고 재시도 (리더기 연결 실패 에러 방지)
            # print(f"오류: {e}") 
            time.sleep(0.5)

if __name__ == "__main__":
    main()