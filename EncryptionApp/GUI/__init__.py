import sys
import logging

from PyQt5 import QtGui
from PyQt5.QtWidgets import \
    QApplication, QPushButton, QLineEdit, QFileDialog, \
    QProgressBar, QGridLayout, QWidget, QTextEdit, QComboBox
from EncryptionApp.communicator import Communicator

logger = logging.getLogger(__name__)


class App(QWidget):
    def __init__(self, as_server: bool):
        super(App, self).__init__()
        self.setWindowTitle(f"Encryption application ({'server' if as_server else 'client'})")
        self.as_server = as_server
        self.communicator = Communicator()
        self.buttons = []
        self.keys_buttons = []
        self.connect_button = None
        self.ip_box = None
        self.message_box = None
        self.filename_box = None
        self.sending_progress = None
        self.sending_mode = None
        self.chat = None
        self.receiving_progress = None
        self.pass_box = None
        self.pass_button = None
        self.home()
        self.show()

    def home(self) -> None:
        layout = QGridLayout()
        self.setLayout(layout)

        self.pass_box = QLineEdit(self)
        self.pass_box.setEchoMode(QLineEdit.Password)
        self.pass_box.resize(150, 20)
        self.pass_button = QPushButton("Confirm password", self)
        self.pass_button.resize(self.pass_button.minimumSizeHint())
        self.pass_button.clicked.connect(self.confirm_password)
        layout.addWidget(self.pass_box, 0, 0)
        layout.addWidget(self.pass_button, 0, 1)

        generate_new_keys_button = QPushButton("Generate new keys", self)
        generate_new_keys_button.resize(generate_new_keys_button.minimumSizeHint())
        generate_new_keys_button.clicked.connect(self.generate_keys)
        self.keys_buttons.append(generate_new_keys_button)

        reuse_keys_button = QPushButton("Use existing keys", self)
        reuse_keys_button.resize(reuse_keys_button.minimumSizeHint())
        reuse_keys_button.clicked.connect(self.reuse_keys)
        self.keys_buttons.append(reuse_keys_button)
        self.disable_keys_buttons()

        layout.addWidget(generate_new_keys_button, 1, 0)
        layout.addWidget(reuse_keys_button, 2, 0)

        self.ip_box = QLineEdit(self)
        self.ip_box.resize(150, 20)
        self.connect_button = QPushButton("Connect", self)
        self.connect_button.resize(self.connect_button.minimumSizeHint())
        self.connect_button.clicked.connect(self.connect_to_ip)
        layout.addWidget(self.ip_box, 3, 0, 1, 2)
        layout.addWidget(self.connect_button, 4, 0)
        self.connect_button.setEnabled(False)

        self.message_box = QLineEdit(self)
        self.message_box.resize(150, 20)
        message_button = QPushButton("Send message", self)
        message_button.resize(message_button.minimumSizeHint())
        message_button.clicked.connect(self.send_message)
        self.buttons.append(message_button)
        layout.addWidget(self.message_box, 5, 0, 1, 2)
        layout.addWidget(message_button, 6, 0)

        self.filename_box = QLineEdit(self)
        self.filename_box.resize(150, 20)
        choose_file_button = QPushButton("Choose file", self)
        choose_file_button.resize(choose_file_button.minimumSizeHint())
        choose_file_button.move(285, 80)
        choose_file_button.clicked.connect(self.choose_file)
        self.buttons.append(choose_file_button)
        layout.addWidget(self.filename_box, 7, 0, 1, 2)
        layout.addWidget(choose_file_button, 7, 2)

        file_button = QPushButton("Send file", self)
        file_button.resize(file_button.minimumSizeHint())
        file_button.clicked.connect(self.send_file)
        self.buttons.append(file_button)
        self.sending_progress = QProgressBar(self)
        self.sending_mode = QComboBox(self)
        self.sending_mode.addItems(["ECB", "CBC", "CFB", "OFB"])
        layout.addWidget(self.sending_progress, 8, 0, 1, 2)
        layout.addWidget(file_button, 8, 2)
        layout.addWidget(self.sending_mode, 8, 3)
        self.disable_sending()

        self.chat = QTextEdit(self)
        self.chat.setReadOnly(True)
        layout.addWidget(self.chat, 9, 0, 3, 3)

    def confirm_password(self):
        self.communicator.password = self.pass_box.text()
        logger.debug(f"Password: {self.pass_box.text()}")
        self.pass_box.clear()
        self.pass_box.setEnabled(False)
        self.pass_button.setEnabled(False)
        self.enable_keys_buttons()

    def generate_keys(self):
        self.communicator.generate_keys()
        self.connect_button.setEnabled(True)
        self.disable_keys_buttons()

    def reuse_keys(self):
        self.communicator.reuse_keys()
        self.connect_button.setEnabled(True)
        self.disable_keys_buttons()

    def disable_keys_buttons(self):
        for button in self.keys_buttons:
            button.setEnabled(False)

    def enable_keys_buttons(self):
        for button in self.keys_buttons:
            button.setEnabled(True)

    def connect_to_ip(self):
        ip, port = self.ip_box.text().split(':')
        self.communicator.init_connection(ip, int(port), self.as_server)
        if self.communicator.data_received_signal:
            self.communicator.data_received_signal.connect(self.update_chat)
        self.enable_sending()
        self.ip_box.setEnabled(False)
        self.connect_button.setEnabled(False)
        logger.info("Connected")

    def update_chat(self, data: str):
        self.chat.append(data)
        logger.info(f"Updated chat with value: {data}")

    def send_message(self) -> None:
        message = self.message_box.text()
        mode = self.sending_mode.currentText()
        self.communicator.send_text(message, mode)
        self.message_box.clear()
        logger.info(f"Sent message: {message}. Mode: {mode}")

    def send_file(self) -> None:
        filename = self.filename_box.text()
        mode = self.sending_mode.currentText()
        self.sending_progress.setValue(0)
        self.communicator.send_file(filename, mode, self.sending_progress)
        self.filename_box.clear()
        logger.info(f"Sent file: {filename}. Mode: {mode}")

    def choose_file(self) -> None:
        filename = QFileDialog.getOpenFileName(self, "Open file", "./")
        self.filename_box.setText(filename[0])

    def disable_sending(self):
        for send_button in self.buttons:
            send_button.setEnabled(False)
        logger.info("Disabled sending")

    def enable_sending(self):
        for send_button in self.buttons:
            send_button.setEnabled(True)
        logger.info("Enabled sending")

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.communicator:
            self.communicator.close_connection()
        event.accept()
        logger.info("Closed app")

    @staticmethod
    def run(as_server: bool) -> None:
        app = QApplication(sys.argv)
        _ = App(as_server)
        sys.exit(app.exec_())
