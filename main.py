"""
Написать утилиту, для проверки SSL сертификата. Никаких ограничений по реализации нет. Но выбор алгоритма и его реализация влияет на решение о приглашении кандидата на второй этап.
Входные данные:
Имеется текстовый файл. В каждой строке записано имя хоста (варианты:
https://hostname
https://hostname/
https://hostname/blabl
hostname/
hostname/blabla
Выходные данные:
На выход требуется создать файл output.csv формата:
Host,SSL validity,Expires
"""
import argparse
from typing import List, Any, Dict
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import csv


def load_ssl_cert(url: str) -> Any:
    if url[:7] == "http://":
        url = "https://%s" % url[7:]
    elif url[:8] != "https://":
        url = "https://%s" % url
    parsed_url = urlparse(url)
    ssl_context = ssl.create_default_context()
    ssl_socket = ssl_context.wrap_socket(socket.socket(), server_hostname=parsed_url.netloc)
    try:
        ssl_socket.connect((parsed_url.netloc, 443))  # if cert is not valid, exception will be raised here
    except ssl.SSLCertVerificationError as e:
        if "self signed certificate" in e.strerror:
            cert = {
                "subject": ((("commonName", parsed_url.netloc),),),
                "ssl_validity": False,
                "notAfter": "self_signed"
            }
            return cert
        raise e
    cert = ssl_socket.getpeercert()
    return cert


def extract_ssl_info(cert: dict) -> Dict[str, str]:
    def extract_host(c: dict) -> str:
        for t in c["subject"]:
            if t[0][0] == "commonName":
                return t[0][1]

    def check_cert_dates(c: dict) -> bool:
        now = datetime.now()
        date_format = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(c["notBefore"], date_format)
        not_after = datetime.strptime(c["notAfter"], date_format)
        if not_before < now < not_after:
            return True
        return False

    ssl_info = {
        "host": extract_host(cert),
        "ssl_validity": cert["notAfter"] != "self_signed" and check_cert_dates(cert),
        "expires": cert["notAfter"]
    }
    return ssl_info


def export_to_csv(info: Dict[str, dict]):
    with open("output.csv", "w") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["host", "ssl_validity", "expires"])
        writer.writeheader()
        for _, row in info.items():
            writer.writerow(row)


def main(urls_list: List[str]):
    hosts_info = {}
    for url in urls_list:
        cert = load_ssl_cert(url)
        info = extract_ssl_info(cert)
        hosts_info[url] = info
    export_to_csv(hosts_info)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("hosts_file_path",
                        help="Path to file with hosts. Only one host can be placed in every row.")
    args = parser.parse_args()
    with open(args.hosts_file_path) as hosts_file:
        hosts = hosts_file.readlines()
    new_hosts = [h.replace("\n", "") for h in hosts]
    main(new_hosts)
