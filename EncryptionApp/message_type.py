from enum import Enum

BYTE_ORDER = 'little'


class MessageType(Enum):
    SESSION_KEY = int(1).to_bytes(4, BYTE_ORDER),
    FILE = int(2).to_bytes(4, BYTE_ORDER),
    TEXT = int(3).to_bytes(4, BYTE_ORDER),
    PUBLIC_KEY = int(4).to_bytes(4, BYTE_ORDER),
