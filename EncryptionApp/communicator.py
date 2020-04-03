import os
import socket
import logging
from tempfile import TemporaryFile

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from PyQt5.QtWidgets import QApplication, QProgressBar
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


from EncryptionApp.receiver_thread import ReceiverThread
import EncryptionApp.message_type as msg_type
from EncryptionApp.message_type import MessageType
from EncryptionApp import cipher_utils
from EncryptionApp import rsa_utils

BYTE_ORDER = msg_type.BYTE_ORDER
KEY_SIZE = 32
AES.block_size = 16

logger = logging.getLogger(__name__)


class Communicator:
    def __init__(self, buffer_size=1024):
        if buffer_size % AES.block_size != 0:
            raise BaseException(f"buffer_size must be divisible by AES.block_size = {AES.block_size}")
        self.buffer_size = buffer_size
        self.session_key = os.urandom(KEY_SIZE)
        self.routing_table = {MessageType.SESSION_KEY.value[0]: self.receive_session_key,
                              MessageType.FILE.value[0]: self.receive_file,
                              MessageType.TEXT.value[0]: self.receive_text,
                              MessageType.PUBLIC_KEY.value[0]: self.receive_public_key}
        self.conn = None
        self.server = None
        self.receiver_thread = None
        self.data_received_signal = None
        self.foreign_public_key = None
        self.foreign_session_key = None
        self.private_key = None
        self.public_key = None
        self.reusing_keys = False

    def generate_keys(self):
        self.private_key, self.public_key = rsa_utils.generate_keys()

    def reuse_keys(self):
        self.reusing_keys = True
        self.private_key, self.public_key = rsa_utils.read_private_key(self.password), rsa_utils.read_public_key()

    def init_connection(self, ip: str, port: int, as_server: bool) -> None:
        if as_server:
            self.server = socket.socket()
            self.server.bind((ip, port))
            self.server.listen(1)
            self.conn, _ = self.server.accept()
            self.listen()
            self.send_public_key()
            if not self.reusing_keys:
                rsa_utils.save_public_key(self.public_key)
                rsa_utils.save_private_key(self.private_key, self.password)
            self.listen()
            self.send_session_key()
            logger.info("Established connection as server")
        else:
            self.conn = socket.socket()
            self.conn.connect((ip, port))
            self.send_public_key()
            self.listen()
            if not self.reusing_keys:
                rsa_utils.save_public_key(self.public_key)
                rsa_utils.save_private_key(self.private_key, self.password)
            self.send_session_key()
            self.listen()
            logger.info("Established connection as client")

        self.receiver_thread = ReceiverThread(self)
        self.receiver_thread.start()

    def close_connection(self) -> None:
        if self.receiver_thread:
            self.receiver_thread.terminate()
            self.receiver_thread.wait()
            logger.info("Receiving thread has stopped")
        if self.conn:
            self.conn.close()
            logger.info("Closed connection")
        if self.server:
            self.server.close()
            logger.info("Closed server")

    def listen(self) -> None:
        message_type = self.receive_type()
        self.route(message_type)

    def route(self, message_type: bytes) -> None:
        try:
            self.routing_table[message_type]()
        except KeyError:
            logger.debug(f"No such key in routing_table. ({message_type})")
            exit(0)

    def receive_type(self) -> bytes:
        message_type = self.receive(4)
        logger.debug(f"Received type: {int.from_bytes(message_type, BYTE_ORDER)}")
        return message_type

    def receive_length(self) -> int:
        message_length = int.from_bytes(self.receive(4), BYTE_ORDER)
        logger.debug(f"Received length: {message_length}")
        return message_length

    def receive_public_key(self) -> None:
        key = self.receive_bytes()
        self.foreign_public_key = RSA.import_key(key)
        logger.debug(f"Received public key: {key}")

    def receive_session_key(self) -> None:
        self.foreign_session_key = self.receive_bytes_with_rsa()
        logger.debug(f"Received session key: {self.foreign_session_key}")

    def receive_bytes(self) -> bytes:
        length = self.receive_length()
        data = self.receive(length)
        return data

    def receive_bytes_with_rsa(self) -> bytes:
        length = self.receive_length()
        encrypted_data = self.receive(length)
        try:
            data = PKCS1_OAEP.new(rsa_utils.read_private_key(self.password)).decrypt(encrypted_data)
        except ValueError:
            data = b'12341234'
        return data

    def receive(self, length: int) -> bytes:
        received_length = 0
        received_data = b''
        while received_length < length:
            received_data += self.conn.recv(length - received_length)
            received_length = len(received_data)
        return received_data

    @cipher_utils.get_mode_and_cipher_to_receive
    def receive_file(self, mode, cipher) -> None:
        file_name = self.receive_bytes_with_rsa()
        file_name = str(file_name, 'utf-8')
        file_size = self.receive_length()
        temp_file = TemporaryFile()

        bytes_received = 0
        while file_size - bytes_received > 0:
            buffer = self.conn.recv(self.buffer_size)
            bytes_received += len(buffer)
            logger.debug(f"Recieved {bytes_received}/{file_size}. Last buffer size: {len(buffer)}")
            temp_file.write(buffer)

        temp_file.seek(0)

        file = open(file_name, 'wb')

        bytes_decrypt = 0
        while file_size - bytes_decrypt > 0:
            if file_size - bytes_decrypt < self.buffer_size:
                buffer = temp_file.read(self.buffer_size)
                buffer = cipher.decrypt(buffer)
                if (file_size - bytes_decrypt) % AES.block_size != 0 and mode in ["ECB", "CBC"]:
                    buffer = unpad(buffer, AES.block_size)
                file.write(buffer)
                break
            buffer = temp_file.read(self.buffer_size)
            buffer = cipher.decrypt(buffer)
            bytes_decrypt += self.buffer_size
            logger.debug(f"Decrypt {bytes_decrypt}/{file_size}")
            file.write(buffer)
        file.close()
        temp_file.close()

        self.data_received_signal.emit(f"Received file: {file_name}")
        logger.info(f"Received file: {file_name}. Mode: {mode}")

    @cipher_utils.get_mode_and_cipher_to_receive
    def receive_text(self, mode, cipher) -> None:
        encrypted_text = self.receive_bytes()
        decrypted_text = cipher.decrypt(encrypted_text)

        if mode in ["ECB", "CBC"]:
            decrypted_text = unpad(decrypted_text, AES.block_size)

        self.data_received_signal.emit(str(decrypted_text, 'utf-8'))

        logger.debug(f"Received encrypted text: {encrypted_text}")
        logger.info(f"Received text: {str(decrypted_text, 'utf-8')}. Mode: {mode}")

    def receive_mode(self) -> str:
        mode = self.receive_bytes_with_rsa()
        return str(mode, 'utf-8')

    def send(self, data: bytes) -> int:
        if self.conn:
            return self.conn.send(data)
        else:
            logger.error("Couldn't sent data, because there is no client connection")

    def send_bytes(self, data: bytes) -> None:
        self.send(len(data).to_bytes(4, BYTE_ORDER))
        self.send(data)

    def send_bytes_with_rsa(self, data: bytes) -> None:
        encrypted_data = PKCS1_OAEP.new(self.foreign_public_key).encrypt(data)
        self.send(len(encrypted_data).to_bytes(4, BYTE_ORDER))
        self.send(encrypted_data)

    def send_public_key(self) -> None:
        self.send(MessageType.PUBLIC_KEY.value[0])
        self.send_bytes(self.public_key.exportKey())
        logger.debug(f"Sent public key {self.public_key.exportKey()}")

    def send_session_key(self) -> None:
        self.send(MessageType.SESSION_KEY.value[0])
        self.send_bytes_with_rsa(self.session_key)
        logger.debug(f"Sent session key {self.session_key}")

    def send_file(self, file_path: str, mode: str, progressbar: QProgressBar = None) -> None:
        self.send(MessageType.FILE.value[0])
        self.send_mode(mode)

        cipher = self.get_cipher_to_encrypt(mode)

        file_name = os.path.basename(file_path)
        file_name_in_bytes = bytes(file_name, 'utf-8')
        self.send_bytes_with_rsa(file_name_in_bytes)
        try:
            file = open(file_path, 'rb')
            file_size = os.path.getsize(file_path)
        except FileNotFoundError:
            file = None
            file_size = 0
            logger.debug(f"Sending empty file due to fact, because file {file_path} does not exist.")

        self.send(file_size.to_bytes(4, BYTE_ORDER))

        bytes_sent = 0
        while file_size - bytes_sent > 0:
            buffer = file.read(self.buffer_size)
            if mode in ["ECB", "CBC"] and len(buffer) % AES.block_size != 0:
                buffer = pad(buffer, AES.block_size)
            bytes_sent += self.send(cipher.encrypt(buffer))
            if progressbar:
                progress = min(int(bytes_sent / file_size * 100), 100)
                progressbar.setValue(progress)
                QApplication.processEvents()
                logger.debug(f"Sent {bytes_sent}/{file_size} of file")
        progressbar.setValue(100)

        if file:
            file.close()
        logger.info(f"Sent file: {file_name}. Mode: {mode}")

    def send_text(self, text: str, mode: str) -> None:
        self.send(MessageType.TEXT.value[0])
        self.send_mode(mode)

        cipher = self.get_cipher_to_encrypt(mode)

        text_in_bytes = bytes(text, 'utf-8')

        if mode in ["ECB", "CBC"]:
            text_in_bytes = pad(text_in_bytes, AES.block_size)
        encrypted_text = cipher.encrypt(text_in_bytes)
        self.send_bytes(encrypted_text)

        logger.debug(f"Sent encrypted text: {encrypted_text}.")
        logger.info(f"Sent text: {text}. Mode: {mode}")

    def send_mode(self, mode: str) -> None:
        mode_in_bytes = bytes(mode, 'utf-8')
        self.send_bytes_with_rsa(mode_in_bytes)

    def get_cipher_to_encrypt(self, mode: str) -> AES:
        if mode == "ECB":
            cipher = AES.new(self.session_key, AES.MODE_ECB)
        elif mode == "CBC":
            cipher = AES.new(self.session_key, AES.MODE_CBC)
            self.send_bytes_with_rsa(cipher.iv)
        elif mode == "CFB":
            cipher = AES.new(self.session_key, AES.MODE_CFB)
            self.send_bytes_with_rsa(cipher.iv)
        elif mode == "OFB":
            cipher = AES.new(self.session_key, AES.MODE_OFB)
            self.send_bytes_with_rsa(cipher.iv)
        else:
            raise BaseException("No such sending mode")
        return cipher
