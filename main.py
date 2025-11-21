import time
from ntag424 import NTAG424  # 같은 폴더에 있는 ntag424.py를 불러옴

def main():
    print("\n=== NTAG 424 DNA 자동 세팅 도구 ===")
    print("👉 리더기에 태그를 올려주세요. (Ctrl+C로 종료)")

    while True:
        try:
            tag = NTAG424()
            if not tag.connect():
                time.sleep(0.5)
                continue
            
            if not tag.select_app():
                tag.disconnect()
                continue

            print("\n⚡ 태그 감지됨! 세팅 시작...")

            if not tag.authenticate_ev2_first(key_no=0):
                print("❌ 인증 실패")
                tag.disconnect()
                time.sleep(2)
                continue
            
            base_url = "https://ntag.nxp.com/424?e="
            picc_data_len = 32
            cmac_str = "&c="
            
            picc_data_offset = len(base_url)
            cmac_offset = picc_data_offset + picc_data_len + len(cmac_str)
            
            # 핵심 설정값 (LSB 순서 적용됨)
            file_access = bytes.fromhex("E000")  # Read=Free
            sdm_opts = bytes([0xC1])
            sdm_access = bytes.fromhex("F000") 

            change_params = (
                sdm_opts +
                sdm_access +
                picc_data_offset.to_bytes(3, 'little') +
                bytes.fromhex("000000") +
                cmac_offset.to_bytes(3, 'little')
            )

            if not tag.change_file_settings(2, file_access, change_params):
                print("❌ 설정 변경 실패")
                tag.disconnect()
                continue
            
            url_template = f"{base_url}{'0'*32}{cmac_str}{'0'*16}"
            url_bytes = url_template.encode('ascii')
            
            ndef_header = bytes([0xD1, 0x01, len(url_bytes) + 1, 0x55, 0x00]) + url_bytes
            tlv_data = bytes([0x03, len(ndef_header)]) + ndef_header + bytes([0xFE])

            if tag.write_data_plain(2, tlv_data):
                print(f"✅ [성공] 태그 세팅 완료!")
                print(f"🔗 URL: {url_template}")
                print("👉 태그를 떼고 다음 태그를 준비하세요.")
            else:
                print("❌ URL 쓰기 실패")

            tag.disconnect()
            time.sleep(3)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"오류: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()