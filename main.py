import gzip
import logging
import re
import subprocess
import sys
import zlib
from datetime import timedelta
from getpass import getpass
from urllib.parse import quote

import mysql.connector
import requests
from requests.exceptions import HTTPError
from dotenv import load_dotenv
from scapy.all import *
from scapy.layers.http import HTTP

logging.basicConfig(filename="output.log", encoding="utf-8", level=logging.DEBUG, format="%(asctime)s - %(levelname)s: %(message)s")

load_dotenv()

HONEYPOT_IPS = ["144.202.123.131"]

def ping_honeypots(username, password):
    if not username or not password:
        raise Exception("Username and password are required!")
    cnx = mysql.connector.connect(user=username, password=password, host="127.0.0.1", database="mysql")
    for honeypot in HONEYPOT_IPS:
        ymd_date = datetime.now().strftime("%Y-%m-%d")
        logging.info(f"Pinging {honeypot} data for {ymd_date}")
        subprocess.run(["rsync", "-azv", f"root@{honeypot}:/root/honeypot/data", f"/home/ubuntu/honeypot_tracker/data/{honeypot}/"])

        path = os.path.join("/", "home", "ubuntu", "honeypot_tracker", "data", honeypot, "data")
        files_to_process = []
        for file in os.listdir(path):
            split = os.path.splitext(file)
            if split[-1] == ".pcap" and split[0].startswith(ymd_date):
                files_to_process.append(os.path.join(path, file))

        for file in files_to_process:
            for packet in rdpcap(file):
                time = float(packet.time)
                timestamp = datetime.fromtimestamp(time)
                src_ip = packet["IP"].src
                src_port = packet["TCP"].sport
                tcp_flag = str(packet["TCP"].flags)
                payload = bytes(packet["TCP"].payload)
                abuseipdb_data = get_ip_data(src_ip)
                region = None
                abuse_confidence_score = None
                if abuseipdb_data is not None:
                    region = abuseipdb_data["data"]["countryCode"]
                    abuse_confidence_score = abuseipdb_data["data"]["abuseConfidenceScore"]

                header_exists = False
                try:
                    header_data_sep = payload.index(b"\r\n\r\n")
                    http_header = payload[payload.index(b"HTTP/1.1"):header_data_sep+2]
                    if not http_header:
                        raise Exception()
                    raw_header = payload[:header_data_sep+2]
                    parsed_header = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", raw_header.decode("utf-8")))
                    if parsed_header["Content-Encoding"] == "gzip":
                        http_payload = payload[header_data_sep+4:]
                        payload = zlib.decompress(http_payload, 16+zlib.MAX_WBITS)
                except:
                    pass


                if packet.time > (datetime.now() + timedelta(minutes=-10)).timestamp() and src_ip != honeypot:
                    cursor = cnx.cursor()
                    insert = ("INSERT INTO attacker_ips (ip, date, target_ip, src_port, tcp_flag, raw_data, abuse_confidence_score, region) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
                    data = (src_ip, timestamp, honeypot, src_port, tcp_flag, payload, abuse_confidence_score, region)
                    cursor.execute(insert, data)
                    cnx.commit()
                    cursor.close()

                    logging.info(f"Discovered {src_ip} on port {src_port} at {timestamp}")

        logging.info(f"Output for honeypot {honeypot} written to {honeypot}.pcap")
        cnx.close()

def get_ip_data(ip):
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip)}", headers={
            "Key": os.getenv("ABUSEIPDB_API_KEY")
        })
        response_json = response.json()
        
        if response.status_code != 200:
            raise HTTPError
        elif "data" not in response_json:
            raise HTTPError()
        return response_json

    except HTTPError:
        return None




if __name__ == '__main__':
    ping_honeypots(os.getenv("USERNAME"), os.getenv("GRAFANA_USER"))
