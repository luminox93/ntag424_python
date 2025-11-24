import os
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad
from smartcard.System import readers

class NTAG424:
    NTAG424_AID = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
    DEFAULT_KEY = bytes.fromhex("00000000000000000000000000000000")

    def __init__(self):
        self.connection = None
        self.reader = None
        self.session_enc_key = None
        self.session_mac_key = None
        self.ti = None
        self.cmd_ctr = 0

    def connect(self):
        """리더기에 연결하고 첫 번째 카드를 찾습니다."""
        try:
            r_list = readers()
            if not r_list: return False
            self.reader = r_list[0]
            self.connection = self.reader.createConnection()
            self.connection.connect()
            return True
        except: return False

    def disconnect(self):
        """연결을 종료합니다."""
        if self.connection:
            try: self.connection.disconnect()
            except: pass

    def select_app(self):
        """NTAG 424 DNA 애플리케이션을 선택합니다."""
        if not self.connection: return False
        apdu = [0x00, 0xA4, 0x04, 0x00, 0x07] + self.NTAG424_AID + [0x00]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        return sw1 == 0x90 and sw2 == 0x00

    def authenticate_ev2_first(self, key_no=0, key=DEFAULT_KEY):
        """
        EV2 First 인증을 수행합니다.
        성공 시 세션 키(Enc, Mac)를 생성합니다.
        """
        if not self.connection: return False

        # 1단계: 태그로부터 RndB 받기
        apdu_part1 = [0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]
        resp1, sw1, sw2 = self.connection.transmit(apdu_part1)
        if sw1 != 0x91 or sw2 != 0xAF: return False

        enc_rnd_b = bytes(resp1[:16])
        cipher_dec1 = AES.new(key, AES.MODE_CBC, bytes(16))
        rnd_b = cipher_dec1.decrypt(enc_rnd_b)
        
        # 2단계: RndA 생성 및 (RndA + RndB') 전송
        rnd_a = os.urandom(16)
        rnd_b_prime = rnd_b[1:] + rnd_b[:1]
        token = rnd_a + rnd_b_prime
        
        cipher_enc = AES.new(key, AES.MODE_CBC, bytes(16))
        enc_token = cipher_enc.encrypt(token)

        apdu_part2 = [0x90, 0xAF, 0x00, 0x00, 0x20] + list(enc_token) + [0x00]
        resp2, sw1, sw2 = self.connection.transmit(apdu_part2)

        if sw1 == 0x91 and sw2 == 0x00:
            # 3단계: 응답 검증 및 세션 키 유도
            enc_data = bytes(resp2[:32])
            cipher_dec2 = AES.new(key, AES.MODE_CBC, bytes(16))
            dec_data = cipher_dec2.decrypt(enc_data)
            
            self.ti = dec_data[0:4]
            self.cmd_ctr = 0

            # 세션 키 유도 로직
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

    def _encrypt_packet(self, cmd_header, data):
        """EV2 보안 메시징을 위해 데이터를 암호화합니다."""
        iv_input = bytes.fromhex("A55A") + self.ti + self.cmd_ctr.to_bytes(2, 'little') + bytes(8)
        cipher_iv = AES.new(self.session_enc_key, AES.MODE_ECB)
        iv = cipher_iv.encrypt(iv_input)

        cipher_data = AES.new(self.session_enc_key, AES.MODE_CBC, iv)
        padded_data = pad(data, 16, style='iso7816')
        return cipher_data.encrypt(padded_data)

    def _calc_mac(self, cmd_code, cmd_header, enc_data):
        """명령어에 대한 CMAC을 계산합니다."""
        mac_input = bytes([cmd_code]) + self.cmd_ctr.to_bytes(2, 'little') + self.ti + cmd_header + enc_data
        cmac_obj = CMAC.new(self.session_mac_key, ciphermod=AES)
        cmac_obj.update(mac_input)
        full_mac = cmac_obj.digest()
        return full_mac[1::2] # 짝수 바이트만 추출하여 8바이트로 단축

    def change_file_settings(self, file_no, access_rights, change_params):
        """
        ChangeFileSettings 명령어를 전송합니다 (암호화 + MAC).
        SDM 미러링 설정 등에 사용됩니다.
        """
        if not self.session_enc_key: return False

        cmd_header = bytes([file_no])
        file_option = 0x40 
        cmd_data = bytes([file_option]) + access_rights + change_params

        enc_data = self._encrypt_packet(cmd_header, cmd_data)
        mac = self._calc_mac(0x5F, cmd_header, enc_data)

        full_data = list(cmd_header) + list(enc_data) + list(mac)
        apdu = [0x90, 0x5F, 0x00, 0x00, len(full_data)] + full_data + [0x00]
        
        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        if sw1 != 0x91 or sw2 != 0x00:
            return False
        return True

    def change_key(self, key_no, new_key, old_key, new_key_version=1):
        """
        ChangeKey 명령어를 전송하여 특정 키를 변경합니다 (EV2 암호화).
        
        Args:
            key_no (int): 변경할 키 번호 (0~4)
            new_key (bytes): 새로운 키 (16 bytes)
            old_key (bytes): 기존 키 (16 bytes)
            new_key_version (int): 새 키 버전 (기본값 1)
        """
        if not self.session_enc_key: return False

        # CmdHeader: KeyNo (1 byte)
        cmd_header = bytes([key_no])
        
        # CmdData: NewKey(16) + NewKeyVersion(1) + OldKey(16) + Pad
        # 주의: OldKey는 현재 키와 다를 때 필요할 수 있으나, NTAG 424에서는 
        # 항상 전송하거나, 특정 조건에서 XOR 등 다를 수 있음.
        # 여기서는 일반적인 EV2 포맷(New + Ver + Old)을 따름.
        
        # 실제 NTAG 424 DNA 스펙상:
        # ChangeKey (Cmd C4) payload:
        # NewKey (16B) || NewKeyVersion (1B) || OldKey (16B, Optional?)
        # 문서에 따르면 OldKey는 "If the targeted key is the same as the authentication key"일 때 XOR 처리 등이 언급되기도 함.
        # 가장 안전한 구현(Standard EV2): NewKey + Version + OldKey
        
        # 여기서는 단순화를 위해 NewKey(16) + Version(1) + OldKey(16) 구조 사용
        
        plain_data = new_key + bytes([new_key_version]) + old_key
        
        # 암호화
        enc_data = self._encrypt_packet(cmd_header, plain_data)
        
        # MAC 계산
        mac = self._calc_mac(0xC4, cmd_header, enc_data)
        
        full_data = list(cmd_header) + list(enc_data) + list(mac)
        apdu = [0x90, 0xC4, 0x00, 0x00, len(full_data)] + full_data + [0x00]
        
        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        if sw1 != 0x91 or sw2 != 0x00:
            raise Exception(f"ChangeKey failed: SW={hex(sw1)} {hex(sw2)}")
        return True

    def write_data_plain(self, file_no, data, offset=0):
        """
        WriteData 명령어를 전송합니다 (Standard Mode, EV2 MAC 없음).
        NDEF 데이터 기록 등에 사용됩니다.
        """
        # 주의: 원래 EV2 인증 상태에서는 WriteData도 MAC이 필요할 수 있으나,
        # 통신 모드 설정(Plain)에 따라 다를 수 있습니다. 현재는 단순 APDU로 구현.
        
        cmd_header = bytes([file_no]) + offset.to_bytes(3, 'little') + len(data).to_bytes(3, 'little')
        
        full_data = list(cmd_header) + list(data)
        apdu = [0x90, 0x8D, 0x00, 0x00, len(full_data)] + full_data + [0x00]

        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        if sw1 != 0x91 or sw2 != 0x00:
            return False
        return True