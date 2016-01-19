import logging
from common import bit9api
from connectors import VirusTotal
from ConfigParser import RawConfigParser
import sys
import requests

# logging
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def main():
    inifile = RawConfigParser({
        "bit9_server_url": "https://localhost",
        "bit9_server_sslverify": False,
        "bit9_server_token": None,
        "vt_api_key": None,
        "retrieve_files": True,
        "upload_binaries_to_vt": False,
        "download_location": None,
        "connector_name": "VirusTotal",
        "log_file": None,
    })
    inifile.read("virustotal.ini")

    config = {}

    config["bit9_server_url"] = inifile.get("bridge", "bit9_server_url")
    config["bit9_server_token"] = inifile.get("bridge", "bit9_server_token")
    config["bit9_server_sslverify"] = inifile.getboolean("bridge", "bit9_server_sslverify")
    config["vt_api_key"] = inifile.get("bridge", "vt_api_key")
    config["retrieve_files"] = inifile.getboolean("bridge", "retrieve_files")
    config["download_location"] = inifile.get("bridge", "download_location")
    config["connector_name"] = inifile.get("bridge", "connector_name")
    config["upload_binaries_to_vt"] = inifile.getboolean("bridge", "upload_binaries_to_vt")

    log_file = inifile.get("bridge", "log_file")
    if log_file:
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(file_handler)

    if not config["vt_api_key"]:
        log.fatal("Cannot start without a valid VirusTotal API key, exiting")
        return 1

    if not config["bit9_server_token"]:
        log.fatal("Cannot start without a valid Bit9 server API token, exiting")
        return 1

    if not config["bit9_server_sslverify"]:
        requests.packages.urllib3.disable_warnings()

    log.info("Configuration:")
    for k,v in config.iteritems():
        log.info("    %-20s: %s" % (k,v))

    bit9 = bit9api.bit9Api(
        config["bit9_server_url"],
        token=config["bit9_server_token"],
        ssl_verify=config["bit9_server_sslverify"]
    )

    vt = VirusTotal.virusTotalConnector(
        bit9,
        vt_token=config["vt_api_key"],
        allow_uploads=config["upload_binaries_to_vt"],  # Allow VT connector to upload binary files to VirusTotal
        connector_name=config["connector_name"],
        download_location=config["download_location"]
    )

    log.info("Starting VirusTotal processing loop")
    vt.start()


if __name__ == '__main__':
    sys.exit(main())

