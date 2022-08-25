# This file is part of CAPE Sandbox - https://github.com/ctxis/CAPE
# See the file 'docs/LICENSE' for copying permission.
#
# This decoder is based on:
# Decryptor POC for Remcos RAT version 2.7.1 and earlier
# By Talos July 2018 - https://github.com/Cisco-Talos/remcos-decoder
# Updates based on work presented here https://gist.github.com/sysopfb/11e6fb8c1377f13ebab09ab717026c87

import base64
import logging
import os
import re
import string
from collections import OrderedDict

import pefile
from Cryptodome.Cipher import ARC4

DESCRIPTION = "Remcos config extractor."
AUTHOR = "threathive,sysopfb,kevoreilly"


# From JPCERT
FLAG = {b"\x00": "Disabled", b"\x01": "Enabled"}

# From JPCERT
idx_list = {
    0: "Host:Port:Password",
    1: "Assigned name",
    2: "Connect interval",
    3: "Install flag",
    4: "Setup HKCU\\Run",
    5: "Setup HKLM\\Run",
    6: "Setup HKLM\\Explorer\\Run",
    7: "Setup HKLM\\Winlogon\\Shell",
    8: "Setup HKLM\\Winlogon\\Userinit",
    9: "Install path",
    10: "Copy file",
    11: "Startup value",
    12: "Hide file",
    13: "Unknown13",
    14: "Mutex",
    15: "Keylog flag",
    16: "Keylog path",
    17: "Keylog file",
    18: "Keylog crypt",
    19: "Hide keylog file",
    20: "Screenshot flag",
    21: "Screenshot time",
    22: "Take Screenshot option",
    23: "Take screenshot title",
    24: "Take screenshot time",
    25: "Screenshot path",
    26: "Screenshot file",
    27: "Screenshot crypt",
    28: "Mouse option",
    29: "Unknown29",
    30: "Delete file",
    31: "Unknown31",
    32: "Unknown32",
    33: "Unknown33",
    34: "Unknown34",
    35: "Unknown35",
    36: "Audio record time",
    37: "Audio path",
    38: "Audio folder",
    39: "Unknown39",
    40: "Unknown40",
    41: "Connect delay",
    42: "Unknown42",
    43: "Unknown43",
    44: "Unknown44",
    45: "Unknown45",
    46: "Unknown46",
    47: "Unknown47",
    48: "Copy folder",
    49: "Keylog folder",
    50: "Unknown50",
    51: "Unknown51",
    52: "Unknown52",
    53: "Unknown53",
    54: "Keylog file max size",
    55: "Unknown55",
    56: "TLS client certificate",
    57: "TLS client private key",
    58: "TLS server certificate",
    59: "Unknown59",
    60: "Unknown60",
    61: "Unknown61",
    62: "Unknown62",
    63: "Unknown63",
    64: "Unknown64",
    65: "Unknown65",
    66: "Unknown66",
}

# From JPCERT
setup_list = {
    0: "Temp",
    2: "Root",
    3: "Windows",
    4: "System32",
    5: "Program Files",
    6: "AppData",
    7: "User Profile",
    8: "Application path",
}

utf_16_string_list = ["Copy file", "Startup value", "Keylog file",
                      "Take screenshot title", "Copy folder", "Keylog folder"]
logger = logging.getLogger(__name__)


def get_rsrc(pe):
    ret = []
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        name = str(resource_type.name if resource_type.name is not None else pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
        if hasattr(resource_type, "directory"):
            for resource_id in resource_type.directory.entries:
                if hasattr(resource_id, "directory"):
                    for resource_lang in resource_id.directory.entries:
                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                        ret.append((name, data, resource_lang.data.struct.Size, resource_type))

    return ret


def get_strings(data, min=4):
    result = ""
    for c in data:
        if chr(c) in string.printable:
            result += chr(c)
            continue
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:
        yield result


def check_version(filedata):
    printable = set(string.printable)

    s = ""
    # find strings in binary file
    slist = get_strings(filedata)

    # find and extract version string e.g. "2.0.5 Pro", "1.7 Free" or "1.7 Light"
    for s in slist:
        if bool(re.search("^\d+\.\d+\.\d+\s+\w+$", s)):
            return s
    return ""


def extract_config(filebuf):
    config = {}
    try:
        pe = pefile.PE(data=filebuf)
        blob = False
        ResourceData = get_rsrc(pe)
        for rsrc in ResourceData:
            if rsrc[0] in ("RT_RCDATA", "SETTINGS"):
                blob = rsrc[1]
                break

        if blob:
            config = {"family": "Remcos", "category": ["rat"]}
            keylen = blob[0]
            key = blob[1: keylen + 1]
            decrypted_data = ARC4.new(key).decrypt(blob[keylen + 1:])
            p_data = OrderedDict()
            config["version"] = check_version(filebuf)

            configs = re.split(rb"\|\x1e\x1e\x1f\|", decrypted_data)

            for i, cont in enumerate(configs):
                if cont in (b"\x00", b"\x01"):
                    # Flag capabilities that are enabled/disabled whether known or not
                    config.setdefault(f"capability_{FLAG[cont].lower()}", []).append(idx_list[i])
                elif i in (9, 16, 25, 37):
                    p_data[idx_list[i]] = setup_list[int(cont)]
                elif i in (56, 57, 58):
                    config.setdefault("other", {})[idx_list[i]] = base64.b64encode(cont)
                elif i == 0:
                    host, port, password = cont.split(b"|", 1)[0].decode().split(":")
                    config.setdefault("tcp", []).append({"server_ip": host, "server_port": port, "usage": "other"})
                    config.setdefault("password", []).append(password)
                else:
                    p_data[idx_list[i]] = cont.decode()

            # Flag paths
            for path_key in [k for k in p_data.keys() if k.endswith("path")]:
                prefix = path_key.split(" ")[0]
                usage = "other"
                if prefix == "Install":
                    usage = "install"
                elif prefix == "Keylog":
                    usage = "logs"

                def get_string(key) -> str:
                    value = p_data.pop(key, None)
                    if key in utf_16_string_list:
                        if isinstance(value, str):
                            value = value.encode()
                        value = value.decode("utf16").strip("\00")
                    return value

                path_parts = [get_string(f"{prefix} {path_part}") for path_part in ["path", "folder", "file"]]
                full_path = os.path.join(*[p for p in path_parts if p])
                config.setdefault("paths", []).append({"path": full_path, "usage": usage})

            for k, v in p_data.items():
                if k in utf_16_string_list:
                    v = v.decode("utf16").strip("\00")
                config.setdefault("other", {})[k] = v

    except pefile.PEFormatError:
        # Not a PE file
        pass
    except Exception as e:
        logger.error(f"Caught an exception: {e}")

    return config


if __name__ == "__main__":
    import sys

    print(extract_config(open(sys.argv[1], "rb").read()))
