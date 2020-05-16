import sys
import logging

from EncryptionApp.GUI import App

logging.basicConfig(level=logging.DEBUG)


def main():
    App.run(as_server=True)


if __name__ == '__main__':
    main()
