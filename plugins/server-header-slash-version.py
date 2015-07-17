"""
httpscan server-header-slash-version plugin

Server Header Slash Version Plugin aims to get the server version from the
HTTP "server" header where the version is spited from the server name with
a slash (/), e.g:

    * mini_httpd/1.19 19dec2003
    * nginx/1.4.6 (Ubuntu)
    * Microsoft-IIS/7.5


Author: Andres Tarantini (atarantini@gmail.com)
"""
import re

REGEX_VERSION = '.*/(.*)$'

def run(host, definition, response):
    r = re.compile(REGEX_VERSION)
    match = r.match(response.headers.get('server').split()[0])
    if not match:
        return definition

    groups = match.groups()
    if groups:
        definition[u'meta'][u'version'] = groups[0]

    return definition