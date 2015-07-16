"""
httpscan nginx-version plugin

author: Andres Tarantini (atarantini@gmail.com)
"""
import re

REGEX_VERSION = 'nginx/(.*) '

def run(host, definition, response):
    r = re.compile(REGEX_VERSION)
    match = r.match(response.headers.get('server'))
    groups = match.groups()
    if groups:
        definition[u'meta'][u'version'] = groups[0]

    return definition