from setuptools import setup, find_packages
from EncryptionApp import __version__
requirements = []

with open("requirements.txt", mode="r") as f:
    for line in f.readlines():
        if line != "\n" and not line.startswith("#"):
            requirements.append(line.strip())

setup(
    name="bsk_project",
    version=__version__,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'bsk_server=EncryptionApp.Server.server:main',
            'bsk_client=EncryptionApp.Client.client:main',
        ]
    },
    install_requires=requirements
)