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
        try:
            r_list = readers()
            if not r_list: return False
            self.reader = r_list[0]
            self.connection = self.reader.createConnection()
            self.connection.connect()
            return True
        except: return False

    def disconnect(self):
        if self.connection:
            try: self.connection.disconnect()
            except: pass

    def select_app(self):
        if not self.connection: return False
        apdu = [0x00, 0xA4, 0x04, 0x00, 0x07] + self.NTAG424_AID + [0x00]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        return sw1 == 0x90 and sw2 == 0x00

    def authenticate_ev2_first(self, key_no=0, key=DEFAULT_KEY):
        if not self.connection: return False

        apdu_part1 = [0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]
        resp1, sw1, sw2 = self.connection.transmit(apdu_part1)
        if sw1 != 0x91 or sw2 != 0xAF: return False

        enc_rnd_b = bytes(resp1[:16])
        cipher_dec1 = AES.new(key, AES.MODE_CBC, bytes(16))
        rnd_b = cipher_dec1.decrypt(enc_rnd_b)
        
        rnd_a = os.urandom(16)
        rnd_b_prime = rnd_b[1:] + rnd_b[:1]
        token = rnd_a + rnd_b_prime
        
        cipher_enc = AES.new(key, AES.MODE_CBC, bytes(16))
        enc_token = cipher_enc.encrypt(token)

        apdu_part2 = [0x90, 0xAF, 0x00, 0x00, 0x20] + list(enc_token) + [0x00]
        resp2, sw1, sw2 = self.connection.transmit(apdu_part2)

        if sw1 == 0x91 and sw2 == 0x00:
            enc_data = bytes(resp2[:32])
            cipher_dec2 = AES.new(key, AES.MODE_CBC, bytes(16))
            dec_data = cipher_dec2.decrypt(enc_data)
            
            self.ti = dec_data[0:4]
            self.cmd_ctr = 0

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
        iv_input = bytes.fromhex("A55A") + self.ti + self.cmd_ctr.to_bytes(2, 'little') + bytes(8)
        cipher_iv = AES.new(self.session_enc_key, AES.MODE_ECB)
        iv = cipher_iv.encrypt(iv_input)

        cipher_data = AES.new(self.session_enc_key, AES.MODE_CBC, iv)
        padded_data = pad(data, 16, style='iso7816')
        return cipher_data.encrypt(padded_data)

    def _calc_mac(self, cmd_code, cmd_header, enc_data):
        mac_input = bytes([cmd_code]) + self.cmd_ctr.to_bytes(2, 'little') + self.ti + cmd_header + enc_data
        cmac_obj = CMAC.new(self.session_mac_key, ciphermod=AES)
        cmac_obj.update(mac_input)
        full_mac = cmac_obj.digest()
        return full_mac[1::2]

    def change_file_settings(self, file_no, access_rights, change_params):
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

    def write_data_plain(self, file_no, data, offset=0):
        if not self.session_enc_key: return False

        cmd_header = bytes([file_no]) + offset.to_bytes(3, 'little') + len(data).to_bytes(3, 'little')
        
        full_data = list(cmd_header) + list(data)
        apdu = [0x90, 0x8D, 0x00, 0x00, len(full_data)] + full_data + [0x00]

        resp, sw1, sw2 = self.connection.transmit(apdu)
        self.cmd_ctr += 1
        
        if sw1 != 0x91 or sw2 != 0x00:
            return False
        return True