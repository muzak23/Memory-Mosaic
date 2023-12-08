# Memory Mosaic
# Logan Nommensen
# Made at Grand Valley State University

# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""
This plugin performs automatic lookups for suspicious processes, files, IP addresses, and more.

Uses the AbuseIPDB API to check IP addresses for malicious activity.
Downloads and checks against the URLhaus and Spam404 databases for malicious IP addresses and URLs.
"""

import re

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
import requests as requests
import ipaddress


def ip_lookup(ip, key=None):
    if ip == "test":
        ip = "127.0.0.1"
    else:
        # we don't want to waste API calls on private IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                return 0
        except (TypeError, ValueError) as e:
            return -1
        # check the databases first
        try:
            with open("malware_filter.txt", "r") as f:
                if ip in f.read():
                    return 1
        except FileNotFoundError:
            pass
    if not key:
        with open("mosaic.env", "r") as f:
            key = f.read().split("=")[1]
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 365
    }
    headers = {
        'Key': key
    }
    answer = requests.get('https://api.abuseipdb.com/api/v2/check', params=params, headers=headers)
    return answer


def setup():
    print("Welcome to Memory Mosaic's setup script!")
    print("This script will help you set up the necessary API keys and download the necessary databases.")
    abuse_ipdb = input("Please enter/update your AbuseIPDB API key or press enter to skip: ")
    if abuse_ipdb != "":
        print("Testing API key...")
        if ip_lookup("test", key=abuse_ipdb).status_code != 200:
            print("Invalid API key. Please try again.")
            return 1
        else:
            with open("mosaic.env", "w") as f:
                f.write("abuse_ipdb=" + abuse_ipdb)
    download_db = input("Would you like to download/update the databases now? Estimated size: 694kb (y/N): ").lower()
    # Downloads list from https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt
    # and https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
    if download_db == "y":
        print("Downloading databases...")
        malware_filter = requests.get("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt")
        spam404 = requests.get("https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt")
        with open("malware_filter.txt", "wb") as f:
            f.write(malware_filter.content + b"\n" + spam404.content)
        print("Databases downloaded!")
    print("Setup complete!")
    print("Run volatility3 -f <memory image> mosaic --help for more information.")
    return 0


class Mosaic(interfaces.plugins.PluginInterface):
    """Performs automatic lookups for suspicious processes, files, IP addresses, and more"""
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel',
                                           description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]
                                           ),
            requirements.BooleanRequirement(name='setup',
                                            description="Run the setup script to input necessary API keys and "
                                                        "download databases",
                                            optional=True
                                            ),
        ]

    def _generator(self):
        try:
            with open('ip_addresses', 'r') as f:
                ips = list(set(f.read().splitlines()))
        except FileNotFoundError:
            with open(self.context.config["automagic.LayerStacker.single_location"][8:], "rb") as f:  
                # Opens the memdump file directly. TODO: Find a better way to do this.
                ips = re.compile(
                    b"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
                ips = ips.findall(f.read())
                ips = list(set(
                    [str(ip[0], "utf-8").lstrip('0') + "." + str(ip[1], "utf-8").lstrip('0') + "." +
                     str(ip[2], "utf-8").lstrip('0') + "." + str(ip[3], "utf-8").lstrip('0') for ip in ips]))
                with open('ip_addresses', 'w') as f2:
                    f2.write("\n".join(ips))
        for ip in ips:
            results = ip_lookup(ip)
            if results == 1:
                yield (0, (ip, "Malicious IP address"))
            elif results == -1 or results == 0:
                pass
            else:
                if results.json()["data"]["abuseConfidenceScore"] >= 25:
                    yield (0, (ip, str(results.json()["data"]["abuseConfidenceScore"])))

    def run(self):
        if self.config.get('setup', None):
            setup()
        try:
            new_user = ""
            if open("mosaic.env", "r").read() == "":
                new_user = input("API keys (mosaic.env) not found. Functionality will be limited. Would you like to"
                                 " run the setup script? (y/N): ").lower()
            if open("malware_filter.txt", "r").read() == "" and new_user != "y":
                new_user = input("Databases (malware_filter.txt) not found. Functionality will be severely limited."
                                 " Would you like to run the setup script? (y/N): ").lower()
        except FileNotFoundError:
            new_user = input("API keys (mosaic.env) and databases (malware_filter.txt) not found. Functionality will"
                             " be severely limited. Would you like to run the setup script? (y/N): ").lower()
        if new_user == "y":
            setup()

        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("IP Address", str),
                                   ("Score", str)],
                                  self._generator())
