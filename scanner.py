"""
httpscan scanner module
"""
import nmap

from logger import log

def scan(hosts, port=22, fast=False):

    results = list()

    # Nmap arguments
    nmap_arguments = ['-n']
    if fast:
        nmap_arguments.append('-T5')

    # Scan
    nm = nmap.PortScanner()
    scan_results = nm.scan(hosts, str(port), arguments=' '.join(nmap_arguments))
    stats = scan_results.get('nmap').get('scanstats')
    log.debug(
        '{up} hosts up, {total} total in {elapsed_time}s'.format(
            up=stats.get('uphosts'),
            total=stats.get('totalhosts'),
            elapsed_time=stats.get('elapsed')
        )
    )

    # Analyze results
    for host, data in list(scan_results.get('scan').items()):
        if data.get('tcp') and data.get('tcp').get(int(port)).get('state') == 'open':
            results.append((host, port))
            #log.debug('{host} Seems to have an HTTP server'.format(host=host))

    return results