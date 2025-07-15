import logging
import subprocess

from dotenv import load_dotenv
from scapy.all import *

logging.basicConfig(
    filename="output.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s: %(message)s",
)

load_dotenv()

HONEYPOT_IPS = {
    "3.19.252.184": "172.31.30.249",  # AWS Ohio
    "54.232.68.11": "172.31.34.248",  # AWS Sao Paulo
    "13.41.212.74": "172.31.9.238",  # AWS London
    # "157.175.27.235": "172.31.4.190",   # AWS Bahrain
    # "13.246.60.122": "172.31.12.15",    # AWS Cape Town
    "18.181.153.25": "172.31.5.210",  # AWS Tokyo
    # "15.207.225.52": "172.31.1.40",     # AWS Mumbai
    "54.169.42.77": "172.31.27.233",  # AWS Singapore
    "18.101.148.182": "172.31.44.146",  # AWS Spain
    # "35.225.206.55": "10.128.0.2",      # GCP Iowa
    "34.133.41.137": "10.128.0.2",  # GCP Iowa (new)
    # "34.88.3.61": "10.166.0.2",         # GCP Finland
    "35.189.27.27": "10.152.0.3",  # GCP Sydney
    "35.220.204.18": "10.170.0.2",  # GCP Hong Kong
    "34.18.58.229": "10.212.0.2",  # GCP Doha
    "20.163.25.107": "10.0.0.4",  # Azure Arizona
    "4.206.220.35": "10.0.0.4",  # Azure Toronto
    # "20.174.33.127": "10.0.0.4",        # Azure Dubai
    # "18.61.113.51": "172.31.24.175",    # AWS Hyderabad
    "52.10.234.47": "172.31.19.173",  # AWS Oregon
    "3.39.103.121": "172.31.44.168",  # AWS Seoul
    # "18.102.109.52": "172.31.39.206",   # AWS Milan
    "108.137.136.67": "172.31.2.164",  # AWS Jakarta
    # "16.51.95.203": "172.31.19.175",    # AWS Melbourne
    # "18.193.239.21": "172.31.16.125",   # AWS Frankfurt
    # "51.20.215.250": "172.31.24.84",    # AWS Stockholm
    # "54.219.16.75": "172.31.10.250",    # AWS Northern California
    "34.176.109.131": "10.194.0.2",  # GCP Santiago
    "34.174.110.171": "10.206.0.2",  # GCP Dallas
    # "34.131.168.12": "10.190.0.2",      # GCP Delhi
    "34.116.169.242": "10.186.0.2",  # GCP Warsaw
    # "34.140.239.55": "10.132.0.2",      # GCP Belgium
    "35.189.251.31": "10.132.0.2",  # GCP Belgium (new)
    # "34.102.105.118": "10.168.0.2",     # GCP Los Angeles
    "34.94.62.242": "10.168.0.2",  # GCP Los Angeles (updated)
    "20.39.241.201": "10.0.0.4",  # Azure Paris
    # "20.224.64.111": "10.0.0.4",        # Azure Netherlands
    "102.37.147.249": "10.0.0.4",  # Azure Johannesburg
    "20.208.128.89": "10.0.0.4",  # Azure Switzerland
    "51.120.245.48": "10.0.0.4",  # Azure Norway
    "4.240.83.130": "10.0.0.4",  # Azure Central India
}


def ping_honeypots():
    """
    Retrieve new data from PCAP files with rsync.
    """
    for honeypot in HONEYPOT_IPS.keys():
        _process_honeypot(honeypot)


def _process_honeypot(honeypot):
    """
    Pull the PCAP files from each honeypot.

    :param str honeypot: The public IP of the honeypot
    """
    logging.info(f"Syncing {honeypot} data")
    subprocess.run(
        [
            "rsync",
            "-azv",
            f"root@{honeypot}:/root/ros-honeypot/data",
            f"/home/ubuntu/honeypot_tracker/data/{honeypot}/",
        ]
    )


if __name__ == "__main__":
    ping_honeypots()
