# Derived from https://github.com/RussianPanda95/Configuration_extractors/blob/main/aurora_config_extractor.py
# A huge thank you to RussianPanda95

import base64
import json
import logging
import re

from maco.model import ExtractorModel as MACOModel

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

patterns = [
    rb"[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?=[0-9]+)",
    rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)",
]

def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="AuroraStealer")
    if raw_config.get('C2'):
        # IP related to C2
        parsed_result.http.append(MACOModel.Http(hostname=raw_config['C2'],
                                                 usage="c2"))
    
    # TODO: We may want to update MACO to account for these?
    # Ref: https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-aurora-stealer
    #parsed_result.other = {k: raw_config[k] for k in ['Loader module', 'Powershell module', 'Grabber'] if raw_config.get(k)}

    # TODO: Unsure what the other possible keys might be and how they should be organized (line 54)
    # For now we'll assign the entirety of the raw config to other
    parsed_result.other = raw_config

    return parsed_result


def extract_config(data):
    config_dict = {}
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, data))

    matches = [match for match in matches if len(match) > 90]

    # Search for the configuration module in the binary
    config_match = re.search(rb"eyJCdWlsZElEI[^&]{0,400}", data)
    if config_match:
        matched_string = config_match.group(0).decode("utf-8")
        decoded_str = base64.b64decode(matched_string).decode()
        for item in decoded_str.split(","):
            key = item.split(":")[0].strip("{").strip('"')
            value = item.split(":")[1].strip('"')
            if key == "IP":
                key = "C2"
            if value:
                config_dict[key] = value

    grabber_found = False

    # Extracting the modules
    for match in matches:
        match_str = match.decode("utf-8")
        decoded_str = base64.b64decode(match_str)

        if b"DW" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "DW":
                    config_dict["Loader module"] = elem

        if b"PS" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "PS":
                    config_dict["PowerShell module"] = elem

        if b"Path" in decoded_str:
            grabber_found = True
            break
        else:
            grabber_match = re.search(b"W3siUGF0aCI6.{116}", data)
            if grabber_match:
                encoded_string = grabber_match.group(0)
                decoded_str = base64.b64decode(encoded_string)
                grabber_str = decoded_str[:95].decode("utf-8", errors="ignore")
                cleanup_str = grabber_str.split("[")[-1].split("]")[0]

                if not grabber_found:
                    grabber_found = True
                    config_dict["Grabber"] = cleanup_str

    return config_dict
