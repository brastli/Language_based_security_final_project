import os
import json
from urllib import request


def readJSON(url):
    '''
    Read a json file from a url
    and return the parsed json object
    '''
    safe_base_dir = os.path.abspath(os.path.dirname(__file__))

    if isinstance(url, str) and url.startswith(('http://', 'https://')):
        response = request.urlopen(url)
    else:
        final_path = os.path.abspath(url)
        if not final_path.startswith(safe_base_dir):
            raise ValueError('Invalid path')
        response = request.urlopen(final_path)

    data = json.loads(response.read())
    return data
