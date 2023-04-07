import json
import yaml

from resources import urlscan, netlas_api, phishstats, shodan_api
from logger import logger


def duplicate_hosts(indicators_results: list) -> list:
    uniq_results = []
    back_hosts = []
    for indicator in indicators_results:
        if indicator["host"] not in back_hosts:
            uniq_results.append(indicator)
            back_hosts.append(indicator["host"])
    return uniq_results


def main(settings: dict):
    indicators_results = []
    url_scan = urlscan.api.Urlscan()
    try:
        urlscan_result = url_scan.search_title_by_keywords(
            settings["keywords"]["title"]
        )
        indicators_results += urlscan_result
        logger.info("get data from Urlscan [len: %s]" % len(urlscan_result))
    except Exception as error:
        logger.error("get data from Urlscan - %s" % error)

    net = netlas_api.api.Netlas()
    try:
        netlas_result = net.favicon_search(settings["favicons"]["sha256hash"])
        netlas_result += net.title_search(settings["keywords"]["title"])
        indicators_results += netlas_result
        logger.info("get data from Netlas [len: %s]" % len(netlas_result))
    except Exception as error:
        logger.error("get data from Netlas - %s" % error)

    phish_stats = phishstats.api.PhishStats()
    try:
        phish_stats_results = phish_stats.search_titles(settings["keywords"]["title"])
        indicators_results += phish_stats_results
        if settings["ips"]["enable"]:
            phish_stats_results = phish_stats.search_urls_by_ip(settings["ips"]["ips"])
            indicators_results += phish_stats_results
        logger.info("get data from PhishStats [len: %s]" % len(indicators_results))
    except Exception as error:
        logger.error("get data from PhishStats - %s" % error)

    _shodan = shodan_api.api.ShodanApi()
    try:
        shoda_results = _shodan.search_hosts_by_favicon(
            settings["favicons"]["murmurhash"]
        )
        shoda_results += _shodan.search_title_by_keywords(settings["keywords"]["title"])
        indicators_results += shoda_results
        logger.info("get data from Shodan [len: %s]" % len(indicators_results))
    except Exception as error:
        logger.error("get data from Shodan - %s" % error)

    indicators_results = duplicate_hosts(indicators_results)
    logger.info("all indicators count: %s" % len(indicators_results))
    return indicators_results


if __name__ == "__main__":
    with open("./settings/settings.yaml", encoding="utf-8") as settings_file:
        settings = yaml.safe_load(settings_file)
    results = main(settings)
    with open("../data/results.json", "w") as results_file:
        json.dump(results, results_file)
