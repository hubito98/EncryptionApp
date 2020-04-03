from Crypto.Cipher import AES


def get_mode_and_cipher_to_receive(receive_function):
    def wrapper(self):
        mode = self.receive_mode()

        if mode == "ECB":
            cipher = AES.new(self.foreign_session_key, AES.MODE_ECB)
        elif mode == "CBC":
            iv = self.receive_bytes_with_rsa()
            cipher = AES.new(self.foreign_session_key, AES.MODE_CBC, iv=iv)
        elif mode == "CFB":
            iv = self.receive_bytes_with_rsa()
            cipher = AES.new(self.foreign_session_key, AES.MODE_CFB, iv=iv)
        elif mode == "OFB":
            iv = self.receive_bytes_with_rsa()
            cipher = AES.new(self.foreign_session_key, AES.MODE_OFB, iv=iv)
        else:
            raise BaseException("No such sending mode")

        receive_function(self, mode, cipher)

    return wrapper
