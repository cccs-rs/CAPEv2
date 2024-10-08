# MIT License
#
# Copyright (c) 2021 enzok
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import tempfile
import zipfile
from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES

try:
    HAVE_UTIL_LIB = True
    from lib.cuckoo.common.utils import store_temp_file
except ModuleNotFoundError as e:
    print(f"Unable to import store_temp_file: {e}")
    HAVE_UTIL_LIB = False

AUTHOR = "enzok"
DESCRIPTION = "Strrat configuration parser"


def unpad(s):
    return s[: -s[-1]]


def unzip_config(filepath):
    data = ""
    if isinstance(filepath, bytes):
        filepath = filepath.decode()
    try:
        with zipfile.ZipFile(filepath) as z:
            for name in z.namelist():
                if "config.txt" in name:
                    data = z.read(name)
                    break
    except Exception:
        return
    return data


def aesdecrypt(data, passkey):
    iv = data[4:20]
    key = pbkdf2_hmac("sha1", passkey, iv, 65536, 16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(data[20:]))


def decode(data):
    decoded = ""
    try:
        data = base64.b64decode(data)
    except Exception as exc:
        return exc
    if data:
        passkey = b"strigoi"
        try:
            decoded = aesdecrypt(data, passkey)
        except Exception:
            return
    return decoded.decode()


def extract_config(data):
    raw_config = {}
    configdata = ""
    tmpzip = ""
    if not HAVE_UTIL_LIB:
        # Will write to a temporary file using tempfile lib
        with tempfile.NamedTemporaryFile() as tmpzip:
            tmpzip.write(data)
            tmpzip.seek(0)
            configdata = unzip_config(tmpzip.name)

    else:
        tmpzip = store_temp_file(data, "badjar.zip", b"strrat_tmp")
        configdata = unzip_config(tmpzip)

    if configdata:
        c2_1, mutex_1, dl_url, c2_2, mutex_2, startup_persist, secondary_persist, skype_persist, license = decode(configdata).split(
            "|"
        )
        raw_config["family"] = "Strrat"
        raw_config["tcp"] = [{"server_domain": c2_1, "usage": "c2"}, {"server_domain": c2_2, "usage": "c2"}]
        raw_config["http"] = [{"uri": dl_url, "usage": "download"}]
        raw_config["mutex"] = [mutex_1, mutex_2]
        raw_config.setdefault("other", {})["license"] = license

        if startup_persist == "true":
            raw_config.setdefault("capability_enabled", []).append("Setup Startup Folder Persistence")
        else:
            raw_config.setdefault("capability_disabled", []).append("Setup Startup Folder Persistence")

        if secondary_persist == "true":
            raw_config.setdefault("capability_enabled", []).append("Secondary Startup Folder Persistence")
        else:
            raw_config.setdefault("capability_disabled", []).append("Secondary Startup Folder Persistence")

        if skype_persist == "true":
            raw_config.setdefault("capability_enabled", []).append("Setup Skype Scheduled Task Persistence")
        else:
            raw_config.setdefault("capability_disabled", []).append("Setup Skype Scheduled Task Persistence")

    return raw_config
