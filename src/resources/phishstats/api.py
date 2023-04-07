import requests
from urllib.parse import urljoin

from src import config


class PhishStats:
    """
    Get indicators from PhishStats data by:
        - search urls by keywords in title
    """

    API_URL = urljoin(config.PHISHSTATS_URL, "/api/phishing")
    RETRIES = 3  # Sometimes the server gives the status 504

    def _requester(self, url: str):
        for retry in range(self.RETRIES):
            response = requests.get(url)
            if response.status_code == 200:
                return response

    @staticmethod
    def _parse_response(response_results: requests.Response) -> list[dict]:
        """
        Parse results from JSON page
        :param response_results:
        :return:
        """
        results = []
        for indicator in response_results.json():
            results.append(
                {
                    "url": indicator["url"],
                    "title": indicator["title"],
                    "host": indicator["host"],
                    "ip": indicator["ip"],
                    "date_update": indicator["date_update"],
                    "query": response_results.url,
                }
            )
        return results

    def _search(self, values: list, query_format: str) -> list[dict]:
        """
        Search by values (keywords, ips, ...)
        :param values:
        :param query_format:
        :return:
        """
        results = []
        for keyword in values:
            url = urljoin(self.API_URL, query_format % keyword)
            response_results = requests.get(url)
            parse_results = self._parse_response(response_results)
            results += parse_results
        return results

    def search_titles(self, keywords: list) -> list[dict]:
        """
        Search urls by keywords in title
        :param keywords:
        :return:
        """
        query = "?_where=(title,like,~%s~)&_sort=-date&_size=100"
        results = self._search(values=keywords, query_format=query)
        return results

    def search_urls_by_ip(self, ips: list) -> list[dict]:
        """
        Search urls by ip
        :param ips:
        :return:
        """
        query = "?_where=(ip,eq,%s)&_sort=-date&_size=100"
        results = self._search(values=ips, query_format=query)
        return results
