"""
    Qakbot decoder for Core/Main DLL
"""

import datetime
import hashlib
import logging
import socket
import struct
from modulefinder import Module

import pefile
from Cryptodome.Cipher import ARC4

DESCRIPTION = "Qakbot configuration parser."
AUTHOR = "threathive, r1n9w0rm"
rule_source = """
rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot Payload"
        cape_type = "QakBot Payload"

    strings:
        $crypto1 = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $sha1_1 = {5? 33 F? [0-9] 89 7? 24 ?? 89 7? 24 ?? 8? [1-3] 24 [1-4] C7 44 24 ?0 01 23 45 67 C7 44 24 ?4 89 AB CD EF C7 44 24 ?8 FE DC BA 98 C7 44 24 ?C 76 54 32 10 C7 44 24 ?0 F0 E1 D2 C3}
        $sha1_2 = {33 C0 C7 01 01 23 45 67 89 41 14 89 41 18 89 41 5C C7 41 04 89 AB CD EF C7 41 08 FE DC BA 98 C7 41 0C 76 54 32 10 C7 41 10 F0 E1 D2 C3 89 41 60 89 41 64 C3}
        $anti_sandbox1 = {8D 4? FC [0-1] E8 [4-7] E8 [4] 85 C0 7E (04|07) [4-7] 33 (C0|D2) 74 02 EB FA}
        $anti_sandbox2 = {8D 45 ?? 50 E8 [2] 00 00 59 68 [4] FF 15 [4] 89 45 ?? 83 7D ?? 0F 76 0C}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
        $decrypt_config3 = {6A 13 8B CE 8B C3 5A 8A 18 3A 19 75 05 40 41 4A 75 F5 0F B6 00 0F B6 09 2B C1 74 05 83 C8 FF EB 0E}
        $call_decrypt = {83 7D ?? 00 56 74 0B FF 75 10 8B F3 E8 [4] 59 8B 45 0C 83 F8 28 72 19 8B 55 08 8B 37 8D 48 EC 6A 14 8D 42 14 52 E8}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}
"""

try:
    HAVE_BLZPACK = True
    from lib.cuckoo.common import blzpack
except (OSError, ModuleNotFoundError) as e:
    print(f"Problem to import blzpack: {e}")
    HAVE_BLZPACK = False

log = logging.getLogger(__name__)

"""
    Config Map
"""
CONFIG = {b"10": "Campaign ID", b"3": "Config timestamp"}

BRIEFLZ_HEADER = b"\x62\x6C\x7A\x1A\x00\x00\x00\x01"
QAKBOT_HEADER = b"\x61\x6c\xd3\x1a\x00\x00\x00\x01"


def parse_build(pe):
    """
    Extract build version from parent of core dll.
    """
    for sec in pe.sections:
        if sec.Name == b".data\x00\x00\x00":
            major, minor = struct.unpack("<II", sec.get_data()[:8])
            return b"%X.%d" % (major, minor)


def parse_config(data):
    """
    Parses the config block into a more human readable format.
    Data looks like this initially b'3=1592498872'
    """
    config = {}
    config_entries = list(filter(None, data.split(b"\r\n")))

    for entry in config_entries:
        try:
            k, v = entry.rsplit(b"=", 1)
            if k == b"3":
                config[CONFIG.get(k, k)] = datetime.datetime.fromtimestamp(int(v)).strftime("%H:%M:%S %d-%m-%Y")
            else:
                k = k[-2:]
                config[CONFIG.get(k, f"ukn_{k.decode()}")] = v
        except Exception:
            log.info("Failed to parse config entry: %s", entry)

    return config


def parse_controllers(data):
    """
    Parses the CNC block into a more human readable format.
    Data looks like this initially 72.29.181.77;0;2078\r\n'
    """
    controllers = []
    for controller in list(filter(None, data.split(b"\r\n"))):
        ip, _, port = controller.decode().split(";")
        controllers.append(f"{ip}:{port}")

    return controllers


def parse_binary_c2(data):
    """
    Parses the binary CNC block format introduced Nov'20
    """
    length = len(data)
    controllers = []
    for c2_offset in range(0, length, 7):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def parse_binary_c2_2(data):
    """
    Parses the binary CNC block format introduced April'21
    """
    c2_data = data

    expected_sha1 = c2_data[:0x14]
    c2_data = c2_data[0x14:]
    actual_sha1 = hashlib.sha1(c2_data).digest()

    if actual_sha1 != expected_sha1:
        log.error("Expected sha1: %s actual: %s", expected_sha1, actual_sha1)
        return

    length = len(c2_data)

    controllers = []
    for c2_offset in range(0, length, 7):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", c2_data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", c2_data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def decompress(data):
    """
    Decompress data with blzpack decompression
    """
    return blzpack.decompress_data(BRIEFLZ_HEADER.join(data.split(QAKBOT_HEADER)))


def decrypt_data(data):
    """
    Decrypts the data using the last 20 bytes as a rc4 key.
    Validates the decryption with the sha1 sum contained within the first 20 bytes of the decrypted data.
    """
    if not data:
        return

    key = data[:0x14]
    decrypted_data = ARC4.new(key).decrypt(data[0x14:])

    if not decrypted_data:
        return

    if hashlib.sha1(decrypted_data[0x14:]).digest() != decrypted_data[:0x14]:
        return

    return decrypted_data[0x14:]


def decrypt_data2(data):
    if not data:
        return

    hash_obj = hashlib.sha1(b"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    return decrypted_data


def decrypt_data3(data):
    if not data:
        return

    hash_obj = hashlib.sha1(b"\\System32\\WindowsPowerShel1\\v1.0\\powershel1.exe")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    return decrypted_data


def extract_config(filebuf):
    end_config = {}
    if not HAVE_BLZPACK:
        return
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
        # image_base = pe.OPTIONAL_HEADER.ImageBase
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                if entry.name is not None:
                    # log.info("id: %s", entry.name)
                    end_config["family"] = "QakBot"
                    controllers = []
                    config = {}
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    res_data = pe.get_memory_mapped_image()[offset : offset + size]
                    if str(entry.name) == "307":
                        # we found the parent process and still need to decrypt/(blzpack) decompress the main DLL
                        dec_bytes = decrypt_data(res_data)
                        decompressed = decompress(dec_bytes)
                        end_config["version"] = parse_build(pe).decode()
                        pe2 = pefile.PE(data=decompressed)
                        for rsrc in pe2.DIRECTORY_ENTRY_RESOURCE.entries:
                            for entry in rsrc.directory.entries:
                                if entry.name is not None:
                                    offset = entry.directory.entries[0].data.struct.OffsetToData
                                    size = entry.directory.entries[0].data.struct.Size
                                    res_data = pe2.get_memory_mapped_image()[offset : offset + size]
                                    if str(entry.name) == "308":
                                        dec_bytes = decrypt_data(res_data)
                                        config = parse_config(dec_bytes)
                                        # log.info("qbot_config: %s", config)
                                        end_config.setdefault("other", {})["Core DLL Build"] = parse_build(pe2).decode()
                                    elif str(entry.name) == "311":
                                        dec_bytes = decrypt_data(res_data)
                                        controllers = parse_controllers(dec_bytes)
                    elif str(entry.name) == "308":
                        dec_bytes = decrypt_data(res_data)
                        config = parse_config(dec_bytes)
                    elif str(entry.name) == "311":
                        dec_bytes = decrypt_data(res_data)
                        controllers = parse_binary_c2(dec_bytes)
                    elif str(entry.name) in ("118", "3719"):
                        dec_bytes = decrypt_data2(res_data)
                        controllers = parse_binary_c2_2(dec_bytes)
                    elif str(entry.name) in ("524", "5812"):
                        dec_bytes = decrypt_data2(res_data)
                        config = parse_config(dec_bytes)
                    elif str(entry.name) in ("18270D2E", "BABA", "103"):
                        dec_bytes = decrypt_data3(res_data)
                        config = parse_config(dec_bytes)
                    elif str(entry.name) in ("26F517AB", "EBBA", "102"):
                        dec_bytes = decrypt_data3(res_data)
                        controllers = parse_binary_c2_2(dec_bytes)
                    end_config["version"] = parse_build(pe).decode()
                    for k, v in config.items():
                        # log.info({ k: v })
                        end_config.setdefault("other", {})[k] = v
                    # log.info("controllers: %s", controllers)
                    for controller in controllers:
                        ip, port = controller.split(":", 1)
                        end_config.setdefault("tcp", []).append({"server_ip": ip, "server_port": port, "usage": "c2"})
    except Exception as e:
        log.warning(e)

    return end_config
