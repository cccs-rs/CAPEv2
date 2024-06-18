from contextlib import suppress

from lib.cuckoo.common.integrations.strings import extract_strings
from maco.model import ExtractorModel as MACOModel

def convert_to_MACO(raw_config: dict) -> MACOModel:
    parsed_result = MACOModel(family="AgentTesla")
    protocol = raw_config.get('Protocol')
    if not protocol:
        return
    elif protocol == "Telegram":
        parsed_result.http.append(
            MACOModel.Http(uri=raw_config["C2"],
                           password=raw_config["Password"],
                           usage="c2")
        )

    elif protocol in ["HTTP(S)", "Discord"]:
        parsed_result.http.append(
            MACOModel.Http(uri=raw_config["C2"],
                           usage="c2")
        )

    elif protocol == "FTP":
        parsed_result.ftp.append(
            MACOModel.FTP(username=raw_config["Username"],
                          password=raw_config["Password"],
                          hostname=raw_config["C2"].replace('ftp://', ''),
                          usage="c2")
        )

    elif protocol == "SMTP":
        parsed_result.smtp.append(
            MACOModel.SMTP(username=raw_config["Username"],
                           password=raw_config["Password"],
                           hostname=raw_config["C2"],
                           port=raw_config["Port"],
                           mail_to=[raw_config["EmailTo"]],
                           usage="c2")
        )
    
    if "Persistence_Filename" in raw_config:
        # TODO: Not sure if this should go under paths with a 'storage' usage..
        parsed_result.other["Persistence_Filename"] = raw_config["Persistence_Filename"]
    
    if "ExternalIPCheckServices" in raw_config:
        # TODO: Looks like it should be added to HTTP since it's for requesting the system's public IP
        parsed_result.other["ExternalIPCheckServices"] = raw_config["ExternalIPCheckServices"]
    

    return parsed_result

def extract_config(data):
    config_dict = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            lines = extract_strings(data=data, on_demand=True, minchars=3)
            if not lines:
                return
        else:
            lines = data.decode().split("\n")
        base = next(i for i, line in enumerate(lines) if "Mozilla/5.0" in line)
        if not base:
            return
        for x in range(1, 32):
            # Data Exfiltration via Telegram
            if "api.telegram.org" in lines[base + x]:
                config_dict["Protocol"] = "Telegram"
                config_dict["C2"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                break
            # Data Exfiltration via Discord
            elif "discord" in lines[base + x]:
                config_dict["Protocol"] = "Discord"
                config_dict["C2"] = lines[base + x]
                break
            # Data Exfiltration via FTP
            elif "ftp:" in lines[base + x]:
                config_dict["Protocol"] = "FTP"
                config_dict["C2"] = lines[base + x]
                config_dict["Username"] = lines[base + x + 1]
                config_dict["Password"] = lines[base + x + 2]
                break
            # Data Exfiltration via SMTP
            elif "@" in lines[base + x]:
                config_dict["Protocol"] = "SMTP"
                if lines[base + x - 2].isdigit() and len(lines[base + x - 2]) <= 5:  # check if length <= highest Port 65535
                    # minchars 3 so Ports < 100 do not appear in strings / TBD: michars < 3
                    config_dict["Port"] = lines[base + x - 2]
                elif lines[base + x - 2] in {"true", "false"} and lines[base + x - 3].isdigit() and len(lines[base + x - 3]) <= 5:
                    config_dict["Port"] = lines[base + x - 3]
                config_dict["C2"] = lines[base + +x - 1]
                config_dict["Username"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                if "@" in lines[base + x + 2]:
                    config_dict["EmailTo"] = lines[base + x + 2]
                break
        # Get Persistence Payload Filename
        for x in range(2, 22):
            if ".exe" in lines[base + x]:
                config_dict["Persistence_Filename"] = lines[base + x]
                break
        # Get External IP Check Services
        externalipcheckservices = []
        for x in range(-4, 19):
            if "ipify.org" in lines[base + x] or "ip-api.com" in lines[base + x]:
                externalipcheckservices.append(lines[base + x])
        if externalipcheckservices:
            config_dict["ExternalIPCheckServices"] = externalipcheckservices

        # Data Exfiltration via HTTP(S)
        temp_match = ["http://", "https://"]  # TBD: replace with a better url validator (Regex)
        if "Protocol" not in config_dict.keys():
            for index, string in enumerate(lines[base:]):
                if string == "Win32_BaseBoard":
                    for x in range(1, 8):
                        if any(s in lines[base + index + x] for s in temp_match):
                            config_dict["Protocol"] = "HTTP(S)"
                            config_dict["C2"] = lines[base + index + x]
                            break
        return config_dict
