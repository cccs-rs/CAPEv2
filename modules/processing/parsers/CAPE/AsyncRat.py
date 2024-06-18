# based on https://github.com/c3rb3ru5d3d53c/mwcfg-modules/blob/master/asyncrat/asyncrat.py

import base64
import binascii
import re
import os
import string
import struct
from contextlib import suppress

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

from maco.model import ExtractorModel as MACOModel

def convert_to_MACO(raw_config: dict) -> MACOModel:
    parsed_result = MACOModel(family="AsyncRAT")
    if not raw_config:
        return

    # Mutex
    parsed_result.mutex.append(raw_config["Mutex"])

    # Version
    parsed_result.version = raw_config["Version"]

    # Was persistence enabled?
    if raw_config['Install'] == 'true':
        parsed_result.capability_enabled.append('persistence')
    else:
        parsed_result.capability_disabled.append('persistence')

    # Installation Path
    if raw_config.get('Folder'):
        parsed_result.paths.append(MACOModel.Path(path=os.path.join(raw_config['Folder'], raw_config['Filename']),
                                                  usage="install"))

    # C2s
    for i in range(len(raw_config.get('C2s', []))):
        parsed_result.http.append(MACOModel.Http(hostname=raw_config["C2s"][i],
                                                 port=int(raw_config["Ports"][i]),
                                                 usage="c2"))
    # Pastebin
    if raw_config.get("Pastebin") not in ["null", None]:
        # TODO: Is it used to download the C2 information if not embedded?
        # Ref: https://www.netskope.com/blog/asyncrat-using-fully-undetected-downloader
        parsed_result.http.append(MACOModel.Http(uri=raw_config["Pastebin"],
                                                 usage="download"))

    return parsed_result



def get_string(data, index, offset):
    return data[index][offset:].decode("utf-8", "ignore")


def get_wide_string(data, index, offset):
    return (data[index][offset:] + b"\x00").decode("utf-16")


def get_salt():
    return bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")


def decrypt(key, ciphertext):
    aes_key = PBKDF2(key, get_salt(), 32, 50000)
    cipher = AES.new(aes_key, AES.MODE_CBC, ciphertext[32 : 32 + 16])
    plaintext = cipher.decrypt(ciphertext[48:]).decode("ascii", "ignore").strip()
    return plaintext


def decrypt_config_string(key, data, index):
    return "".join(filter(lambda x: x in string.printable, decrypt(key, base64.b64decode(data[index][2:]))))


def decrypt_config_list(key, data, index):
    result = decrypt_config_string(key, data, index)
    if result == "null":
        return []
    return result.split(",")


def extract_config(filebuf):
    config = {}
    addr = re.search(b"BSJB", filebuf).start()
    if not addr:
        return

    strings_offset = struct.unpack("<I", filebuf[addr + 0x40 : addr + 0x44])[0]
    strings_size = struct.unpack("<I", filebuf[addr + 0x44 : addr + 0x48])[0]
    data = filebuf[addr + strings_offset : addr + strings_offset + strings_size].split(b"\x00\x00")
    if len(data) < 7:
        return

    key = None
    offset = 3
    with suppress(binascii.Error):
        key = base64.b64decode(get_string(data, 6, offset))
    if not key:
        offset = 1
        with suppress(binascii.Error):
            key = base64.b64decode(get_string(data, 7, offset))
        if not key:
            return

    with suppress(Exception):
        config = {
            "C2s": decrypt_config_list(key, data, 2),
            "Ports": decrypt_config_list(key, data, 1),
            "Version": decrypt_config_string(key, data, 3),
            "Folder": get_wide_string(data, 5, offset),
            "Filename": get_wide_string(data, 6, offset),
            "Install": decrypt_config_string(key, data, 4),
            "Mutex": decrypt_config_string(key, data, 8),
            "Pastebin": decrypt(key, base64.b64decode(data[12][1:])).encode("ascii").replace(b"\x0f", b"").decode(),
        }

    return config


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
