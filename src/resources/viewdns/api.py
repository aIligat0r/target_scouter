from urllib.parse import urljoin

from src import config
from src.utils.session import session


class ViewDNS:
    """
    get data from https://viewdns.info/ using API
    """

    @staticmethod
    def _get_url(query: str):
        """
        get API url with search method
        """
        api_url = urljoin(
            config.VIEWDNS_API_URL,
            query + "&output=json&apikey=%s" % config.VIEWDNS_API_KEY,
        )
        return api_url

    @staticmethod
    def _requester(url: str):
        response = session.get(url)
        return response.json()

    def search_domains_by_ips(self, ips: list[str]) -> list:
        """
        Reverse IP Lookup - search domains on ip
        """
        results = []
        for ip in ips:
            query = "/reverseip/?host=%s" % ip
            api_url = self._get_url(query)
            print(api_url)
            response = self._requester(api_url)
            for domain in response["response"]["domains"]:
                results.append(
                    {
                        "host": domain["name"],
                        "last_resolved": domain["last_resolved"],
                        "ip": ip,
                    }
                )
        return results
