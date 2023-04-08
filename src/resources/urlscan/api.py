import datetime

import requests
from urllib.parse import urljoin

from src import config
from src.utils.session import session


class Urlscan:
    """
    Get indicators from Urlscan data by:
        - search urls by keywords in title
    """

    HEADERS = {"API-Key": config.URLSCAN_API_KEY}
    API_URL = urljoin(config.URLSCAN_URL, "/api/v1/search/")
    DATE = "[%s TO %s]" % (
        (datetime.datetime.now() - datetime.timedelta(days=30)).strftime("%Y-%m-%d"),
        datetime.datetime.now().strftime("%Y-%m-%d"),
    )

    @staticmethod
    def _parse_results(response_results: requests.Response) -> list[dict]:
        """
        Parse response results from JSON page
        :param response_results:
        :return: [{url: str, title: str, host: str, screenshot: str, query: str}, ...]
        """
        results = []
        for indicator in response_results.json()["results"]:
            results.append(
                {
                    "url": indicator["page"]["url"],
                    "title": indicator["page"]["title"],
                    "host": indicator["page"]["domain"],
                    "ip": indicator["page"]["ip"],
                    "time": indicator["task"]["time"],
                    "screenshot": indicator["screenshot"],
                    "result": indicator["result"],
                    "query": response_results.url,
                }
            )
        return results

    def _requester(self, url: str):
        response = session.get(url, headers=self.HEADERS)
        return response

    def _search(self, values: list, query_format: str) -> list[dict]:
        """
        Search titles from Urlscan by keywords
        :param query_format:
        :param values:
        :return: [{url: str, title: str, host: str, screenshot: str, query: str}, ...]
        """
        results = []
        for keyword in values:
            url = urljoin(self.API_URL, query_format % (keyword, self.DATE))
            response_results = self._requester(url)
            results += self._parse_results(response_results)
        return results

    def search_title_by_keywords(self, keywords: list) -> list[dict]:
        """
        Search urls by keywords in title
        :return:
        """
        query = '?q=page.title:"%s" AND date:%s'
        results = self._search(values=keywords, query_format=query)
        return results

    def search_urls_by_ip(self, ips: list) -> list[dict]:
        """
        Search urls by ip
        :return:
        """
        query = "?q=page.ip:%s AND date:%s"
        results = self._search(values=ips, query_format=query)
        return results

    def search_url_by_keywords(self, keywords: list):
        """
        Search urls by keywords in url
        :return:
        """
        results = []
        query = "?q=page.url:%s AND date:%s"
        for keyword in keywords:
            url = urljoin(self.API_URL, query % (keyword, self.DATE))
            response_results = self._requester(url)
            for indicator in response_results.json()["results"]:
                _indicator = {
                    "url": indicator["task"]["url"],
                    "host": indicator["task"]["domain"],
                    "time": indicator["task"]["time"],
                    "result": indicator["result"],
                    "screenshot": indicator["screenshot"],
                }
                if "title" in indicator["page"]:
                    _indicator.update({"title": indicator["page"]["title"]})
                results.append(_indicator)
        return results
