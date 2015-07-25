#!/usr/bin/env python
"""
httpscan

Scan networks for HTTP servers
"""
import argparse
import imp
import json
import re
import string
import warnings
from glob import glob
from os.path import basename, exists
from sys import exit

import requests

from scanner import scan
from logger import log

warnings.filterwarnings("ignore")

PORT = 80


#
# Main
#
if __name__ == '__main__':
    ###########################################################################
    # Bootstrap
    #

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Scan networks for HTTP servers')
    parser.add_argument('hosts', help='An IP address for a hostname or network, ex: 192.168.1.1 for single host or 192.168.1.1-254 for network.')
    parser.add_argument('--fast', help='Change timeout settings for the scanner in order to scan faster (T5).', default=False, action='store_true')
    parser.add_argument('--definitions-create', help='Create a definition for a given host', default=False, action='store_true')
    args = parser.parse_args()

    ###########################################################################
    # Create new definition from host if "--definitions-create" argument is set
    #
    if args.definitions_create:
        url = 'http://{host}/'.format(host=args.hosts)
        try:
            response = requests.get(url, timeout=5, verify=False)
        except (requests.exceptions.RequestException, requests.exceptions.SSLError) as e:
            log.debug('{url} request error: {exc}'.format(url=url, exc=e))
            exit()

        valid_charcters = string.ascii_lowercase + string.digits
        name = ''.join([char for char in response.headers.get('server', '').lower() if char in valid_charcters])
        if not name:
            log.debug('Unable to find proper information to create a definition of {url}'.format(url=url))
            exit()
        definition_path = 'definitions/{}.json'.format(name)
        template = json.loads(open('definitions/template.json', 'r').read())
        template['name'] = name
        template['rules']['headers']['server'] = [response.headers.get('server')]
        if exists(definition_path):
            log.warning('Definition {name} already exists'.format(name=name))
            exit()
        # Save definition
        f = file(definition_path, 'w')
        f.write(json.dumps(template, indent=4))
        print template
        exit()


    ###########################################################################
    # Scan
    #
    log.debug('Scanning...')
    hosts = scan(args.hosts, PORT, args.fast)
    if not hosts:
        log.debug('No hosts found with port {port} open.'.format(port=PORT))
        exit()

    ###########################################################################
    # Fingerprint
    #

    # Load definitions DB
    definitions_db = {}
    for definition_path in glob('definitions/*.json'):
        definitions_db[basename(definition_path[:-5])] = json.loads(
            open(definition_path).read())

    # Compile regexp
    regexp_header_server = []
    for name, definition in definitions_db.iteritems():
        for r in definition.get('rules').get('headers').get('server'):
            regexp_header_server.append((re.compile(r), name))
    regexp_body = []
    for name, definition in definitions_db.iteritems():
        if definition.get('rules').get('body'):
            for r in definition.get('rules').get('body'):
                regexp_body.append((re.compile(r), name))

    for host, port in hosts:
        # Make HTTP request
        url = 'http://{host}/'.format(host=host)
        try:
            response = requests.get(url, timeout=5, verify=False)
        except (requests.exceptions.RequestException, requests.exceptions.SSLError) as e:
            log.debug('{url} request error: {exc}'.format(
                url=url,
                exc=e
            ))
            continue

        identity = None

        #
        # Analyze response
        #

        # HTTP server header
        header_server = response.headers.get('server')
        if header_server:
            for regexp, http_server in regexp_header_server:
                if regexp.search(header_server):
                    identity = definitions_db.get(http_server)
                    break

        # Body
        body = response.text
        if body and not identity:
            for regexp, http_server in regexp_body:
                if regexp.search(body):
                    identity = definitions_db.get(http_server)
                    break

        # If identity found, search and run plugins. Default identity otherwise.
        if identity:
            if identity.get('plugins') and isinstance(identity.get('plugins'), list):
                for plugin_name in identity.get('plugins'):
                    try:
                        plugin_information = imp.find_module(plugin_name, ['plugins'])
                        if plugin_information:
                            plugin = imp.load_module(
                                'plugins.{name}'.format(name=plugin_name),
                                *plugin_information
                            )
                            identity = plugin.run(host, identity, response)
                    except (ImportError, Exception) as e:
                        log.warning(
                            'Unable to load plugin "{}" for "{}" definition: {}'.format(
                                plugin_name, identity.get('name'), e
                            )
                        )
        else:
            identity = {'name': header_server}

        log.info('{host}|{definition_name}|{definition_meta}'.format(
            host=host,
            definition_name=identity.get('name'),
            definition_meta=identity.get('meta')
            )
        )