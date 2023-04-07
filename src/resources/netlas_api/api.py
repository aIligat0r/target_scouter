from time import sleep
from urllib.parse import urlparse

import netlas

from src import config


class Netlas:
    """
    Get indicators from netlas_api data by:
        - search urls by keywords in content body
        - search urls by favicons sha256 hash
    """

    def __init__(self):
        self.netlas_connection = netlas.Netlas(api_key=config.NETLAS_API_KEY)

    def _response_search(
        self, query: str, values: list, size=1000, indices="5"
    ) -> list[dict]:
        """
        Search response methods by queries
        indices:
            "5" - ~last_month (by default)
            "5,4,3,2" - all time
            http.title - title
        :return: [{query: str, url: str, host: str, ip: str, last_update: str, ...}]
        """
        results = []
        fields = "uri,ip,http.title"
        for value in values:
            search_query = '%s:"%s"' % (query, value)
            netlas_query = self.netlas_connection.stat(
                query=search_query, group_fields=fields, size=size, indices=indices
            )
            for result in netlas_query["aggregations"]:
                result = result["key"]
                url = result[0].replace(":80", "").replace(":443", "")
                host = urlparse(url).netloc
                ip = result[1]
                title = result[2]
                results.append(
                    {
                        "url": url,
                        "host": host,
                        "ip": ip,
                        "title": title,
                        "query": search_query,
                    }
                )
            sleep(5)
        return results

    def body_search(self, keywords: list) -> list[dict]:
        """
        Search keywords in content (query: http.body)
        :param keywords:
        :return: [{query: str, url: str, host: str, ip: str, last_update: str, ...}]
        """
        results = self._response_search(query="http.body", values=keywords)
        return results

    def title_search(self, keywords: list):
        results = self._response_search(query="http.title", values=keywords)
        return results

    def favicon_search(self, sha256_list: list):
        """
        Search favicons by favicons sha256 hash (query: http.favicon.hash_sha256)
        :return: [{query: str, url: str, host: str, ip: str, last_update: str, ...}]
        """
        for sha in sha256_list:
            assert isinstance(sha, str)
            assert len(sha) == 64
        results = self._response_search(
            query="http.favicon.hash_sha256", values=sha256_list
        )
        return results
