#!/usr/bin/env python
"""
httpscan

Scan networks for HTTP servers
"""
import argparse
import logging
import json
from glob import glob

import re
from os.path import basename
import nmap
import requests


PORT = 80
BATCH_TEMPLATE_DEFAULT = '{host}'


def out(hostname, fingerprint, template='{host}'):
    """
    Return a string to be used as output when "--batch" mode is enabled

    :param hostname:    String with the hostname
    :param template:    String with a template, defaults to "{host}" [1]

    :return:    String to be used as output

    [1] See https://docs.python.org/2/library/string.html#formatstrings
    """
    return template.format(host=hostname, fingerprint=fingerprint)

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
    parser.add_argument('--batch', help='Batch mode will only output hosts, handy to use with unix pipes.', default=False, action='store_true')
    parser.add_argument('--batch-template', help='Change batch mode output template, default is "{host}". Available context variables: host, username, password. Ex: "{username}@{host}" will return "root@192.168.0.1" as output when running in batch mode.', default=BATCH_TEMPLATE_DEFAULT)
    args = parser.parse_args()

    # If "--batch-template" is sent, assume that the user wants batch mode
    if args.batch_template != BATCH_TEMPLATE_DEFAULT:
        args.batch = True

    # Setup logging
    logger = logging.getLogger('httpscan')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler('httpscan.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if args.batch:
        logger.setLevel(logging.INFO)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    ###########################################################################
    # Scan
    #
    logger.debug('Scanning...')
    hosts = list()

    nmap_arguments = ['-n']
    if args.fast:
        nmap_arguments.append('-T5')
    nm = nmap.PortScanner()
    scan = nm.scan(args.hosts, str(PORT), arguments=' '.join(nmap_arguments))
    stats = scan.get('nmap').get('scanstats')
    logger.debug(
        '{up} hosts up, {total} total in {elapsed_time}s'.format(
            up=stats.get('uphosts'),
            total=stats.get('totalhosts'),
            elapsed_time=stats.get('elapsed')
        )
    )
    for host, data in list(scan.get('scan').items()):
        if data.get('tcp') and data.get('tcp').get(PORT).get('state') == 'open':
            hosts.append((host, PORT))
            logger.debug('{host} Seems to have an HTTP server'.format(host=host))

    if not hosts:
        logger.debug('No hosts found with port {port} open.'.format(port=PORT))
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
    regexp_map = []
    for name, definition in definitions_db.iteritems():
        for r in definition.get('rules').get('headers').get('server'):
            regexp_map.append((re.compile(r), name))

    for host, port in hosts:
        # Make HTTP request
        url = 'http://{host}/'.format(host=host)
        try:
            response = requests.get(url)
        except requests.exceptions.SSLError:
            logger.debug('{} SSL error'.format(url))
            continue

        identity = None

        # Analyze response (HTTP server header)
        header_server = response.headers.get('server')
        if header_server:
            for regexp, http_server in regexp_map:
                if regexp.search(header_server):
                    identity = definitions_db.get(http_server)
                    break

        # Default identity
        if not identity:
            identity = {'name': header_server}

        logger.info('{host}|{name}|{definition}'.format(
            host=host,
            name=identity.get('name'),
            definition=identity
            )
        )
        """
        print out(
            host,
            headers_server_fingerprint,
            template=args.batch_template
        )
        """