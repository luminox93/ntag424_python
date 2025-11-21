import sys
import os
from binascii import hexlify

# src 경로 설정
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

def verify_packet_structures():
    print("=== 🧪 패킷 구조 검증 (Plain vs Encrypted) ===\n")

    # 공통 설정
    uid_offset = 32
    cmac_offset = 80
    
    # =================================================================
    # Case 1: 평문 미러링 (AN12196 예제 기준)
    # 조건: MetaRead 권한이 'E'(Free) 일 때
    # =================================================================
    print("[Case 1] 평문 미러링 (AN12196 예제)")
    
    sdm_opts_plain = bytes([0xC1])      # Bit 7(UID) + Bit 6(Ctr) + Bit 0(ASCII)
    sdm_access_plain = bytes.fromhex("F121") # MetaRead=F(No?), 예제는 권한이 섞여있음
    # 핵심: AN12196 예제는 'Plain' 모드라 UID Offset과 Ctr Offset이 존재함
    
    # [데이터 구조]
    # Option(1) + Access(2) + UID_Off(3) + Ctr_Off(3) + MAC_In_Off(3) + MAC_Off(3) = 15 bytes
    # (Enc Off/Len은 옵션 꺼져서 없음)
    
    packet_plain = (
        sdm_opts_plain +
        sdm_access_plain +
        uid_offset.to_bytes(3, 'little') +      # UID Offset (Plain용)
        bytes.fromhex("430000") +               # Ctr Offset (Plain용)
        # PICCData Offset은 없음 (Plain이니까)
        bytes.fromhex("000000") +               # MAC Input Offset
        cmac_offset.to_bytes(3, 'little')       # MAC Offset
    )
    
    print(f"  - 생성된 패킷 길이: {len(packet_plain)} bytes")
    # AN12196 예제 데이터 길이와 비교 (예제는 18~19바이트일 수 있음, 옵션에 따라 다름)
    # 여기서는 '구조적 논리'만 봅니다.
    
    
    # =================================================================
    # Case 2: 암호화 미러링 (우리가 Main에서 쓸 것)
    # [cite_start]조건: MetaRead 권한이 '0~4'(Key) 일 때 [cite: 2179-2180]
    # =================================================================
    print("\n[Case 2] 암호화 미러링 (실전용)")
    
    sdm_opts_enc = bytes([0xC1]) # 옵션은 같아도
    sdm_access_enc = bytes.fromhex("00F0") # MetaRead=0 (Key0) -> 암호화 모드 발동!
    
    # [데이터 구조] - 여기가 중요합니다!
    # Option(1) + Access(2) + PICCData_Off(3) + MAC_In_Off(3) + MAC_Off(3)
    # UID Offset과 Ctr Offset은 사라지고, PICCData Offset 하나로 통합됨.
    
    packet_enc = (
        sdm_opts_enc +
        sdm_access_enc +
        uid_offset.to_bytes(3, 'little') +      # PICCData Offset (Enc용)
        bytes.fromhex("000000") +               # MAC Input Offset
        cmac_offset.to_bytes(3, 'little')       # MAC Offset
    )
    
    print(f"  - 생성된 패킷 길이: {len(packet_enc)} bytes")
    print(f"  - 패킷 내용(Hex): {hexlify(packet_enc).decode().upper()}")

    # 검증 로직
    # 암호화 모드에서는 불필요한 Offset 필드가 빠져서 길이가 더 짧아야 정상입니다.
    # 예상 길이: 1(Opt) + 2(Acc) + 3(PICC) + 3(In) + 3(MAC) = 12 Bytes
    
    expected_len = 12
    if len(packet_enc) == expected_len:
        print(f"  ✅ 검증 성공: 암호화 모드 패킷 길이가 {expected_len}바이트로 정확합니다.")
    else:
        print(f"  ❌ 검증 실패: 길이가 {expected_len}이어야 하는데 {len(packet_enc)}입니다.")
        print("     -> 불필요한 필드(UID/Ctr Offset 등)가 섞여있는지 확인하세요.")

if __name__ == "__main__":
    verify_packet_structures()