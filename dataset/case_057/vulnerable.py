import re
from urllib.parse import urlparse

import requests
from flask import request


def full_ssrf():
    '''
    Get the subdomain from the request and use it as the url, make a request to the url, and return the response
    '''
    subdomain = request.args["subdomain"]

    if not re.fullmatch(r"[A-Za-z0-9-]+", subdomain):
        raise ValueError("Invalid subdomain")
    if subdomain.startswith("-") or subdomain.endswith("-"):
        raise ValueError("Invalid subdomain")

    host = subdomain + ".example.com"
    url = "https://" + host + "/data/"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != host or parsed.path != "/data/" or parsed.query or parsed.fragment:
        raise ValueError("Invalid URL")

    response = requests.get(url)
    return response.text
