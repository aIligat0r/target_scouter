import datetime

from shodan import Shodan

from src import config


class ShodanApi:
    """
    Search hosts from shodan using API
    """

    api = Shodan(config.SHODAN_API_KEY)
    after_date = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime(
        "%d/%m/%Y"
    )

    @staticmethod
    def parse_entity(resource: dict, query: str):
        """
        entity parser
        """
        if resource["port"] == 433:
            url = "https://" + resource["ip_str"]
        else:
            url = "http://" + resource["ip_str"]
        formatted_out = {
            "url": url,
            "title": resource["http"]["title"],
            "host": resource["ip_str"],
            "hostnames": resource["hostnames"],
            "domains": resource["domains"],
            "country": resource["location"]["country_name"],
            "query": query,
        }
        if "favicon" in resource["http"]:
            formatted_out.update({"favicon": resource["http"]["favicon"]["hash"]})
        return formatted_out

    def _search(self, query: str, keywords: list) -> list[dict]:
        """
        search query
        """
        results = []
        for keyword in keywords:
            # query = 'after:%s AND %s:"%s"' % (self.after_date, query, keyword)
            query = '%s:"%s"' % (query, keyword)
            response_generator = self.api.search_cursor(query)
            for resource in response_generator:
                formatted = self.parse_entity(resource, query)
                results.append(formatted)
        return results

    def search_title_by_keywords(self, keywords: list) -> list[dict]:
        """
        search hosts by keyword in title
        """
        results = self._search("http.title", keywords)
        return results

    def search_hosts_by_favicon(self, murmur_hash: list[int]) -> list[dict]:
        """
        search hosts by favicons murmurhash
        """
        results = self._search("http.favicon.hash", murmur_hash)
        return results
