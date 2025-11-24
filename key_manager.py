from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# 마스터 키 저장소
# 현재는 테스트를 위해 모든 키를 00으로 설정했습니다.
MASTER_KEYS = {
    0: bytes.fromhex("00000000000000000000000000000000"),
    1: bytes.fromhex("00000000000000000000000000000000"),
    2: bytes.fromhex("00000000000000000000000000000000"),
    3: bytes.fromhex("00000000000000000000000000000000"),
    4: bytes.fromhex("00000000000000000000000000000000"),
}

def get_derived_key(key_no, uid):
    """
    UID를 기반으로 태그 고유의 키를 파생(Diversification)합니다.
    
    알고리즘: AES-CMAC(MasterKey, UID)
    이 방식을 사용하면 태그마다 서로 다른 키를 가지게 되어,
    하나의 태그 키가 탈취되더라도 전체 시스템의 보안이 위협받지 않습니다.
    
    Args:
        key_no (int): 파생할 키 번호 (0~4)
        uid (bytes): 태그의 고유 ID (7 bytes)
        
    Returns:
        bytes: 파생된 16바이트 키
    """
    # 해당 번호의 마스터 키 가져오기 (없으면 기본 00 키)
    master_key = MASTER_KEYS.get(key_no, bytes(16))
    
    # AES-CMAC 알고리즘을 사용하여 키 파생
    # 입력 데이터(Msg)로 UID를 사용
    cobj = CMAC.new(master_key, ciphermod=AES)
    cobj.update(uid)
    
    derived_key = cobj.digest()
    
    return derived_key
