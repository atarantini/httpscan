"""
httpscan basic-auth plugin

HTTP Basic Authentication plugin will try to login using HTTP "Authorization"
header (http://tools.ietf.org/html/rfc2617) with credentials from definition
meta "default_username" and "default_password" values.

How it works:

    * See if the initial HTTP request response status code was 401

    * Try to login with username and password defined in the definition

    * If response to login is ~200 will raise warning in the logs and add the
      credentials to the definition


Author: Andres Tarantini (atarantini@gmail.com)
"""
import requests

from logger import log


def run(host, port, definition, response):
    meta = definition.get('meta')
    username = meta.get('default_username')
    password = meta.get('default_password')
    if response.status_code == 401 and (username or password):
        url = 'http://{host}:{port}/'.format(host=host, port=port)
        try:
            authenticated_response = requests.get(
                url,
                timeout=5,
                verify=False,
                auth=(
                    username,
                    password
                )
            )
            # print authenticated_response, authenticated_response.text[0:50]
        except (requests.exceptions.RequestException, requests.exceptions.SSLError) as e:
            raise e

        if authenticated_response.ok:
            definition['meta']['username'] = username
            definition['meta']['password'] = password
            log.warning(
                'http://{host}:{port}/ {name} | {plugin}: default credentials '
                '({username}:{password})'.format(
                    host=host,
                    port=port,
                    name=definition.get('name'),
                    plugin=__name__,
                    username=username,
                    password=password
                )
            )

        del definition['meta']['default_username']
        del definition['meta']['default_password']

    return definition
