import json
import yaml

from resources import urlscan, netlas_api, phishstats, shodan_api, viewdns, virustotal
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
        urlscan_result = []
        if settings["keywords"]["enable"]:
            urlscan_result = url_scan.search_title_by_keywords(
                settings["keywords"]["title"]
            )
            logger.info(
                "get data from Urlscan by keywords (len: %s)" % len(urlscan_result)
            )
        if settings["ips"]["enable"]:
            urlscan_result += url_scan.search_urls_by_ip(settings["ips"]["ips"])
            logger.info("get data from Urlscan by ips (len: %s)" % len(urlscan_result))
        indicators_results += urlscan_result

    except Exception as error:
        logger.error("get data from Urlscan - %s" % error)

    net = netlas_api.api.Netlas()
    try:
        netlas_result = []
        if settings["favicons"]["enable"]:
            netlas_result = net.favicon_search(settings["favicons"]["sha256hash"])
            logger.info(
                "get data from Netlas by favicons  (len: %s)" % len(netlas_result)
            )
        if settings["keywords"]["enable"]:
            netlas_result += net.title_search(settings["keywords"]["title"])
            logger.info(
                "get data from Netlas by keywords  (len: %s)" % len(netlas_result)
            )
        indicators_results += netlas_result
    except Exception as error:
        logger.error("get data from Netlas - %s" % error)

    phish_stats = phishstats.api.PhishStats()
    try:
        phish_stats_results = []
        if settings["keywords"]["enable"]:
            phish_stats_results = phish_stats.search_titles(
                settings["keywords"]["title"]
            )
            logger.info(
                "get data from PhishStats by keywords (len: %s)"
                % len(phish_stats_results)
            )
        if settings["ips"]["enable"]:
            phish_stats_results += phish_stats.search_urls_by_ip(settings["ips"]["ips"])
            logger.info(
                "get data from PhishStats by ips (len: %s)" % len(phish_stats_results)
            )
        indicators_results += phish_stats_results
    except Exception as error:
        logger.error("get data from PhishStats - %s" % error)

    _shodan = shodan_api.api.ShodanApi()
    try:
        shodan_results = []
        if settings["favicons"]["enable"]:
            shodan_results = _shodan.search_hosts_by_favicon(
                settings["favicons"]["murmurhash"]
            )
            logger.info(
                "get data from Shodan by favicons (len: %s)" % len(shodan_results)
            )
        if settings["keywords"]["enable"]:
            shodan_results += _shodan.search_title_by_keywords(
                settings["keywords"]["title"]
            )
            logger.info(
                "get data from Shodan by keywords (len: %s)" % len(shodan_results)
            )
        indicators_results += shodan_results
    except Exception as error:
        logger.error("get data from Shodan - %s" % error)

    _viewdns = viewdns.api.ViewDNS()
    try:
        viewdns_results = []
        if settings["ips"]["enable"]:
            viewdns_results = _viewdns.search_domains_by_ips(settings["ips"]["ips"])
        indicators_results += viewdns_results
        logger.info("get data from ViewDNS by ips (len: %s)" % len(viewdns_results))
    except Exception as error:
        logger.error("get data from ViewDNS - %s" % error)

    _vt = virustotal.api.VirusTotal()
    try:
        _vt_results = []
        if settings["ips"]["enable"]:
            _vt_results = _vt.get_resolutions(settings["ips"]["ips"])
            logger.info("get data from VirusTotal by ips (len: %s)" % len(_vt_results))
        indicators_results += _vt_results
    except Exception as error:
        logger.error("get data from VirusTotal - %s" % error)

    indicators_results = duplicate_hosts(indicators_results)
    logger.info("all indicators count: %s" % len(indicators_results))
    return indicators_results


if __name__ == "__main__":
    with open("./settings/settings.yaml", encoding="utf-8") as settings_file:
        settings = yaml.safe_load(settings_file)
    results = main(settings)
    with open("../data/results.json", "w") as results_file:
        json.dump(results, results_file)
