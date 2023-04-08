from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import requests


session = requests.Session()
retries = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retries, pool_maxsize=50))
session.mount("https://", HTTPAdapter(max_retries=retries, pool_maxsize=50))
session.verify = False
