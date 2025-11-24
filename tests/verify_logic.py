import sys
import os
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad

# src 폴더 경로 추가
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from ntag424_python.ntag424 import NTAG424

def verify_logic():
    print("=== 🧪 NXP 문서 데이터로 로직 검증 ===")
    
    # 1. 가상의 태그 객체 생성
    tag = NTAG424()
    
    # 2. 문서(AN12196 Table 18)에 나온 '정답' 데이터 강제 주입
    # 이 값들은 문서에서 "이렇게 설정했을 때 이런 암호문이 나와야 한다"고 명시한 값들입니다.
    
    # [상황 설정] 인증은 이미 끝났고, 아래 세션 키가 생성되었다고 가정
    # SesAuthENCKey (Step 3, Table 18)
    tag.session_enc_key = unhexlify("1309C877509E5A215007FF0ED19CA564")
    # SesAuthMACKey (Step 2, Table 18)
    tag.session_mac_key = unhexlify("4C6626F5E72EA694202139295C7A7FC7")
    
    # TI (Transaction ID) - Step 6
    tag.ti = unhexlify("9D00C4DF")
    
    # CmdCtr (명령어 카운터) - Step 5 (0100 -> Little Endian: 0001 아님, 문서상 0100)
    # 주의: 문서는 LSB First라고 되어있음. 0x0100 (십진수 256이 아니라 카운터 1을 의미하는 표기일 수 있음)
    # Table 18 Step 5: CmdCtr = 0100
    # 하지만 실제 카운터는 정수 1임. to_bytes(2, 'little') 하면 b'\x01\x00'이 됨.
    tag.cmd_ctr = 1 

    # 3. ChangeFileSettings 명령어 만들기 (Table 18 Step 7)
    # CmdHeader: 02
    # CmdData: 40 00 E0 C1 F1 21 20 00 00 43 00 00 43 00 00
    file_no = 2
    cmd_data_plain = unhexlify("4000E0C1F121200000430000430000")
    
    # --- 검증 1: 암호화 (Encryption) ---
    # 문서의 정답 (Step 11): 61B6D97903566E84C3AE5274467E89EA
    cmd_header = bytes([file_no])
    enc_data = tag._encrypt_packet(cmd_header, cmd_data_plain)
    
    print(f"내 코드의 암호화 결과: {hexlify(enc_data).decode().upper()}")
    expected_enc = "61B6D97903566E84C3AE5274467E89EA"
    
    if hexlify(enc_data).decode().upper() == expected_enc:
        print("✅ 암호화 로직 일치")
    else:
        print(f"❌ 암호화 불일치! (정답: {expected_enc})")
        return

    # --- 검증 2: MAC 계산 (가장 중요) ---
    # 문서의 정답 (Step 14): D799B7C1A0EF7A04
    # 여기서 틀리면 아까 그 0x1E 에러가 나는 겁니다.
    mac = tag._calc_mac(0x5F, cmd_header, enc_data)
    
    print(f"내 코드의 MAC 결과 : {hexlify(mac).decode().upper()}")
    expected_mac = "D799B7C1A0EF7A04"
    
    if hexlify(mac).decode().upper() == expected_mac:
        print("✅ MAC 로직 일치 (짝수 바이트 추출 성공)")
    else:
        print(f"❌ MAC 불일치! (정답: {expected_mac})")
        print("👉 힌트: _calc_mac 함수에서 full_mac[1::2] 처리가 제대로 안 됐을 수 있음.")
        return

    print("\n🎉 검증 완료! 이제 리더기에 연결해도 됩니다.")

if __name__ == "__main__":
    verify_logic()
