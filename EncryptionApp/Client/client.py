import sys
import logging

from EncryptionApp.GUI import App

logging.basicConfig(level=logging.DEBUG)


def main():
    App.run(as_server=False)


if __name__ == '__main__':
    main()
