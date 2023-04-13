import socket

import vt

from src import config


class VirusTotal:
    """
    get data from VirusTotal using API
    """

    def __init__(self):
        self.client = vt.Client(config.VIRUSTOTAL_API_KEY)

    @staticmethod
    def resolver(host: str, ips: list) -> bool:
        """
        resolve current ip (data from VT is sometimes old)
        """
        try:
            res = socket.gethostbyname_ex(host)
            for ip in ips:
                if ip in res[-1]:
                    return res[-1]
        except socket.gaierror:
            return False
        return False

    def parse_iter(self, iter_host: dict, ips: list):
        curr_ip = self.resolver(iter_host["attributes"]["host_name"], ips)
        if curr_ip:
            return {
                "host": iter_host["attributes"]["host_name"],
                "ip": iter_host["attributes"]["ip_address"],
                "ips": curr_ip,
                "host_name_last_analysis_stats": iter_host["attributes"]["host_name_last_analysis_stats"],
            }

    def get_resolutions(self, ips: list):
        """
        get resolutions
        """
        results = []
        for ip in ips:
            iterator = self.client.iterator(
                "/ip_addresses/%s/resolutions" % ip, batch_size=40, limit=10000
            )
            for iter_host in iterator:
                iter_host = iter_host.to_dict()
                parsed_host = self.parse_iter(iter_host, ips)
                if parsed_host:
                    results.append(parsed_host)
        self.client.close()
        return results
