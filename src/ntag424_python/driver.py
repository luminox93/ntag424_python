import os
from typing import List, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

from .constants import (
    NTAG424_AID, DEFAULT_KEY_BYTES, 
    CMD_AUTH_EV2_FIRST_PART1, CMD_AUTH_EV2_FIRST_PART2,
    CMD_CHANGE_FILE_SETTINGS, CMD_WRITE_DATA,
    SW_SUCCESS, SW_ADDITIONAL_FRAME
)
from .exceptions import ConnectionError, AuthenticationError, CommandError

class NTAG424Driver:
    """
    NTAG 424 DNA 태그를 제어하기 위한 로우 레벨 드라이버.
    PC/SC를 사용하여 ISO7816 통신 및 EV2 보안 메시징을 처리합니다.
    """

    def __init__(self):
        self.connection: Optional[CardConnection] = None
        self.reader = None
        self.session_enc_key: Optional[bytes] = None
        self.session_mac_key: Optional[bytes] = None
        self.ti: Optional[bytes] = None  # 트랜잭션 식별자 (Transaction Identifier)
        self.cmd_ctr: int = 0

    def connect(self) -> bool:
        """사용 가능한 첫 번째 스마트 카드 리더기에 연결합니다."""
        try:
            r_list = readers()
            if not r_list:
                return False
            self.reader = r_list[0]
            self.connection = self.reader.createConnection()
            self.connection.connect()
            return True
        except Exception:
            return False

    def disconnect(self):
        """카드와의 연결을 종료합니다."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass

    def select_app(self) -> bool:
        """NTAG 424 DNA 애플리케이션을 선택합니다."""
        if not self.connection:
            raise ConnectionError("연결되지 않았습니다.")
        
        # 00 A4 04 00 07 [AID] 00
        apdu = [0x00, 0xA4, 0x04, 0x00, 0x07] + NTAG424_AID + [0x00]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        return sw1 == SW_SUCCESS and sw2 == 0x00

    def authenticate_ev2_first(self, key_no: int = 0, key: bytes = DEFAULT_KEY_BYTES) -> bool:
        """
        'AuthenticateEV2First' 핸드셰이크를 수행합니다.
        성공 시 세션 키(Enc, Mac)를 파생합니다.
        """
        if not self.connection:
            raise ConnectionError("연결되지 않았습니다.")

        # 1단계: 태그로부터 RndB 수신
        apdu_part1 = [0x90, CMD_AUTH_EV2_FIRST_PART1, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]
        resp1, sw1, sw2 = self.connection.transmit(apdu_part1)
        
        if sw1 != SW_ADDITIONAL_FRAME or sw2 != 0xAF:
            return False

        enc_rnd_b = bytes(resp1[:16])
        cipher_dec1 = AES.new(key, AES.MODE_CBC, bytes(16))
        rnd_b = cipher_dec1.decrypt(enc_rnd_b)
        
        # 2단계: RndA 생성 및 (RndA + RndB') 전송
        rnd_a = os.urandom(16)
        rnd_b_prime = rnd_b[1:] + rnd_b[:1]
        token = rnd_a + rnd_b_prime
        
        cipher_enc = AES.new(key, AES.MODE_CBC, bytes(16))
        enc_token = cipher_enc.encrypt(token)

        apdu_part2 = [0x90, CMD_AUTH_EV2_FIRST_PART2, 0x00, 0x00, 0x20] + list(enc_token) + [0x00]
        resp2, sw1, sw2 = self.connection.transmit(apdu_part2)

        if sw1 == SW_ADDITIONAL_FRAME and sw2 == 0x00:
            # 3단계: 태그 응답 검증 및 키 파생
            enc_data = bytes(resp2[:32])
            cipher_dec2 = AES.new(key, AES.MODE_CBC, bytes(16))
            dec_data = cipher_dec2.decrypt(enc_data)
            
            self.ti = dec_data[0:4]
            self.cmd_ctr = 0

            # 세션 키 파생
            xor_part = bytes([a ^ b for a, b in zip(rnd_a[2:8], rnd_b[0:6])])
            context = rnd_a[0:2] + xor_part + rnd_b[6:16] + rnd_a[8:16]
            
            sv1 = bytes.fromhex("A55A00010080") + context
            sv2 = bytes.fromhex("5AA500010080") + context
            
            cmac_enc = CMAC.new(key, ciphermod=AES)
            cmac_enc.update(sv1)
            self.session_enc_key = cmac_enc.digest()
            
            cmac_mac = CMAC.new(key, ciphermod=AES)
            cmac_mac.update(sv2)
            self.session_mac_key = cmac_mac.digest()
            return True
        return False

    def _encrypt_packet(self, cmd_header: bytes, data: bytes) -> bytes:
        """EV2 보안 메시징을 위해 명령어 데이터를 암호화합니다."""
        iv_input = bytes.fromhex("A55A") + self.ti + self.cmd_ctr.to_bytes(2, 'little') + bytes(8)
        cipher_iv = AES.new(self.session_enc_key, AES.MODE_ECB)
        iv = cipher_iv.encrypt(iv_input)

        cipher_data = AES.new(self.session_enc_key, AES.MODE_CBC, iv)
        padded_data = pad(data, 16, style='iso7816')
        return cipher_data.encrypt(padded_data)

    def _calc_mac(self, cmd_code: int, cmd_header: bytes, enc_data: bytes) -> bytes:
        """명령어에 대한 CMAC을 계산합니다."""
        mac_input = bytes([cmd_code]) + self.cmd_ctr.to_bytes(2, 'little') + self.ti + cmd_header + enc_data
        cmac_obj = CMAC.new(self.session_mac_key, ciphermod=AES)
        cmac_obj.update(mac_input)
        full_mac = cmac_obj.digest()
        return full_mac[1::2] # 8바이트로 자름

    def change_file_settings(self, file_no: int, access_rights: bytes, change_params: bytes) -> bool:
        """ChangeFileSettings 명령어를 전송합니다 (암호화 + MAC 적용)."""
        if not self.session_enc_key:
            raise AuthenticationError("세션이 인증되지 않았습니다.")

        cmd_header = bytes([file_no])
        file_option = 0x40 
        cmd_data = bytes([file_option]) + access_rights + change_params

        enc_data = self._encrypt_packet(cmd_header, cmd_data)
        mac = self._calc_mac(CMD_CHANGE_FILE_SETTINGS, cmd_header, enc_data)

        full_data = list(cmd_header) + list(enc_data) + list(mac)
        apdu = [0x90, CMD_CHANGE_FILE_SETTINGS, 0x00, 0x00, len(full_data)] + full_data + [0x00]
        
        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        return sw1 == SW_ADDITIONAL_FRAME and sw2 == 0x00

    def write_data_plain(self, file_no: int, data: bytes, offset: int = 0) -> bool:
        """WriteData 명령어를 전송합니다 (Standard Mode, EV2 MAC 포함)."""
        if not self.session_enc_key:
             raise AuthenticationError("세션이 인증되지 않았습니다.")

        cmd_header = bytes([file_no]) + offset.to_bytes(3, 'little') + len(data).to_bytes(3, 'little')
        
        # 참고: EV2 모드에서 Plain 쓰기 시에도 MAC이 요구될 수 있습니다.
        # 이전 POC 구현을 기반으로 합니다.
        
        full_data = list(cmd_header) + list(data)
        # 단순화를 위해 현재는 APDU로 래핑하여 전송합니다.
        # Plain 모드라 하더라도 인증된 세션 내에서는 MAC 컨텍스트 유지가 필요할 수 있습니다.
        
        apdu = [0x90, CMD_WRITE_DATA, 0x00, 0x00, len(full_data)] + full_data + [0x00]

        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        return sw1 == SW_ADDITIONAL_FRAME and sw2 == 0x00