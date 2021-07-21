from urllib.parse import urlsplit
import sys
import re


def convert_punnycode(url: str) -> str:
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    try:
        return host.encode('utf8').decode('idna')
    except UnicodeDecodeError as ex:
        return host.encode('idna').decode('utf8')
